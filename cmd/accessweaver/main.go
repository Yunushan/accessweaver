package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/packageupgrade"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/servicehost"
	"github.com/Yunushan/accessweaver/internal/uiaccess"
	"github.com/Yunushan/accessweaver/web"
)

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func execute(args []string) error {
	if len(args) == 2 && args[0] == "service-host" {
		return servicehost.Run(args[1])
	}
	if len(args) == 0 {
		args = []string{"ui"}
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage()
		return nil
	}
	if args[0] == "version" {
		if len(args) == 2 && args[1] == "--json" {
			return printJSON(buildinfo.Current())
		}
		if len(args) != 1 {
			return errors.New("usage: accessweaver version [--json]")
		}
		fmt.Printf("AccessWeaver %s (%s %s)\n", buildinfo.Version, runtime.GOOS, runtime.GOARCH)
		return nil
	}
	if args[0] == "ui" {
		if err := uiaccess.RequireUnelevated(); err != nil {
			return err
		}
	}
	runtimeLease, leaseErr := packageupgrade.AcquireInstalledRuntime()
	if leaseErr != nil {
		return leaseErr
	}
	if runtimeLease != nil {
		defer runtimeLease.Close()
	}
	if args[0] == "managed" {
		return managedCommand(args[1:])
	}
	if args[0] == "audit" {
		return auditCommand(args[1:])
	}
	root, err := profile.DefaultRoot()
	if err != nil {
		return err
	}
	if env := os.Getenv("ACCESSWEAVER_HOME"); env != "" {
		root = env
	}
	if args[0] == "backup" {
		return backupCommand(args[1:], root)
	}
	// Catalog, validation, diagnostics and workflow metadata must also work in
	// read-only environments without creating or seeding a profile store.
	var store *profile.Store
	switch args[0] {
	case "ui", "profiles", "show", "preview", "import", "run":
		store, err = profile.NewStore(root)
		if err != nil {
			return err
		}
		if args[0] == "ui" || args[0] == "run" || args[0] == "import" {
			controller, lockErr := filelock.TryAcquire(filepath.Join(root, ".controller.lock"))
			if errors.Is(lockErr, filelock.ErrBusy) {
				return errors.New("another AccessWeaver controller is using this data directory; close it before starting a controller or importing through the CLI")
			}
			if lockErr != nil {
				return fmt.Errorf("lock controller data directory: %w", lockErr)
			}
			defer controller.Close()
		}
		if err = store.Seed(profile.Builtins()); err != nil {
			return err
		}
	}
	switch args[0] {
	case "system":
		return systemCommand(args[1:], root)
	case "ui":
		manager := engine.NewManager(root)
		server, err := api.New(store, manager, web.Assets)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serveDesktop(ctx, server, os.Stdout)
	case "engines":
		for _, e := range engine.Catalog() {
			fmt.Printf("%-14s %-10s platforms=%-30s  %s\n", e.ID, e.Kind, strings.Join(e.Platforms, ","), e.Source)
		}
	case "profiles":
		items, err := store.List()
		if err != nil {
			return err
		}
		for _, p := range items {
			fmt.Printf("%-24s %-14s %s\n", p.ID, p.Engine, p.Name)
		}
	case "show":
		if len(args) < 2 {
			return errors.New("usage: accessweaver show PROFILE_ID")
		}
		p, err := store.Get(args[1])
		if err != nil {
			return err
		}
		return printJSON(p)
	case "preview":
		if len(args) != 2 {
			return errors.New("usage: accessweaver preview PROFILE_ID")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		p, err := store.GetContext(ctx, args[1])
		if err != nil {
			return err
		}
		plan, err := engine.PreviewContext(ctx, p, root)
		if err != nil {
			return err
		}
		return printJSON(plan)
	case "validate":
		if len(args) < 2 {
			return errors.New("usage: accessweaver validate FILE.json")
		}
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		p, err := profile.Decode(f)
		if err != nil {
			return err
		}
		fmt.Println("Valid profile:", p.ID)
		return nil
	case "import":
		if len(args) < 2 {
			return errors.New("usage: accessweaver import FILE.json")
		}
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		p, err := profile.Decode(f)
		if err != nil {
			return err
		}
		if err = store.Save(p); err != nil {
			return err
		}
		fmt.Println("Imported:", p.ID)
	case "doctor":
		return doctorCommand(args[1:])
	case "run":
		if len(args) < 2 {
			return errors.New("usage: accessweaver run PROFILE_ID")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		p, err := store.GetContext(ctx, args[1])
		if err != nil {
			return err
		}
		return runForegroundEngine(ctx, p, engine.NewManager(root), os.Stdout)
	default:
		return fmt.Errorf("unknown command %q; use help", args[0])
	}
	return nil
}

type foregroundEngineRun interface {
	Done() <-chan struct{}
	Wait(context.Context) (engine.RunResult, error)
}

var errEngineLaunchOutput = errors.New("engine launch notice could not be written")

func runForegroundEngine(ctx context.Context, p profile.Profile, manager *engine.Manager, out io.Writer) error {
	stopOutput := observeAuditOutputPipes()
	defer stopOutput()
	if err := ctx.Err(); err != nil {
		return err
	}
	run, err := manager.StartTrackedContext(ctx, p)
	if err != nil {
		return err
	}
	return finishAcceptedForegroundEngine(ctx, run, manager.Stop, out, os.Stderr)
}

// Notice output is part of this foreground scope. Once accepted, even a failed
// notice must retain the exact launch until terminal observation.
func finishAcceptedForegroundEngine(ctx context.Context, run foregroundEngineRun, stop func() error, out, feedback io.Writer) error {
	const notice = "Process launched. This does not guarantee functional routing or connection.\n"
	if n, err := io.WriteString(out, notice); err != nil || n != len(notice) {
		return errors.Join(errEngineLaunchOutput, observeForegroundEngine(context.Background(), run, stop, feedback, true))
	}
	return observeForegroundEngine(ctx, run, stop, feedback, false)
}

// Waiting follows this exact launch. A stop error is not terminal observation:
// retain ownership and wait for Done even after cancellation or output failure.
func waitForegroundEngine(ctx context.Context, run foregroundEngineRun, stop func() error) error {
	return observeForegroundEngine(ctx, run, stop, os.Stderr, false)
}

// Fault notifications carry no terminal proof. They only provide fixed local
// feedback while this foreground scope continues to own the pending launch.
type foregroundEngineFault interface {
	PendingError() error
	Fault() <-chan struct{}
}

func observeForegroundEngine(ctx context.Context, run foregroundEngineRun, stop func() error, feedback io.Writer, stopImmediately bool) error {
	if ctx == nil || run == nil || run.Done() == nil || stop == nil {
		return engine.ErrRunUnavailable
	}
	done := run.Done()
	var fault <-chan struct{}
	if source, ok := run.(foregroundEngineFault); ok {
		fault = source.Fault()
	}
	warned := false
	warn := func() {
		select {
		case <-done:
			return
		default:
		}
		if !warned {
			warned = true
			_, _ = io.WriteString(feedback, "Engine shutdown is not confirmed. Waiting for the owned launch; this command remains active.\n")
		}
	}
	ctxDone := ctx.Done()
	var stopErr error
	requestStop := func() {
		select {
		case <-done:
			ctxDone = nil
			return
		default:
		}
		stopErr = stop()
		warn()
		ctxDone = nil // Cancellation cannot abandon an accepted launch.
	}
	if stopImmediately {
		requestStop()
	}
	if source, ok := run.(foregroundEngineFault); ok && source.PendingError() != nil {
		warn()
	}
	terminal := func() error {
		result, waitErr := run.Wait(context.Background())
		return errors.Join(stopErr, waitErr, foregroundEngineTerminal(result))
	}
	for {
		// Prefer an already published observation over concurrent cancellation.
		select {
		case <-done:
			return terminal()
		default:
		}
		select {
		case <-done:
			return terminal()
		case <-ctxDone:
			select {
			case <-done:
				return terminal()
			default:
			}
			requestStop()
		case <-fault:
			if source, ok := run.(foregroundEngineFault); ok && source.PendingError() != nil {
				warn()
			}
			fault = nil
		}
	}
}

func foregroundEngineTerminal(result engine.RunResult) error {
	if result.LifecycleErr != nil {
		return fmt.Errorf("engine lifecycle: %w", errors.Join(result.LifecycleErr, result.PolicyErr, result.WaitErr))
	}
	if result.Reason == engine.RunFailed || result.Reason == engine.RunPolicyRevoked {
		return fmt.Errorf("engine exited: %w", errors.Join(result.PolicyErr, result.WaitErr))
	}
	return nil
}

func usage() {
	fmt.Printf(`AccessWeaver %s — local-first network access manager

  accessweaver ui                  Start responsive local dashboard
  accessweaver engines             Show supported engine adapters
  accessweaver profiles            List editable profiles
  accessweaver show ID             Print profile JSON
  accessweaver preview ID          Review launch plan without starting an engine
  accessweaver validate FILE.json  Validate a profile
  accessweaver import FILE.json    Import profile into local store
  accessweaver backup create|inspect|restore [options]
                                  Encrypted profile backup and new-directory restore
  accessweaver doctor [options] [HOST]
                                  Direct/proxy TCP/TLS or explicit UDP/STUN checks
  accessweaver run ID              Explicitly start one engine in foreground
  accessweaver audit help          Verify segments, record desktop actions or export audit JSONL
  accessweaver managed             Review/sign/verify administrator policy documents
  accessweaver system              Show Windows installation/repair commands
  accessweaver version [--json]    Print runtime and source build identity

Optional environment: ACCESSWEAVER_HOME=<private directory>
                      ACCESSWEAVER_NO_BROWSER=1
`, buildinfo.Version)
}
func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = io.Copy(os.Stdout, bytes.NewReader(append(b, '\n')))
	return err
}
func openBrowser(addr string) {
	var name string
	var args []string
	switch runtime.GOOS {
	case "windows":
		name = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", addr}
	case "darwin":
		name = "open"
		args = []string{addr}
	default:
		name = "xdg-open"
		args = []string{addr}
	}
	if bin, err := exec.LookPath(name); err == nil {
		_ = exec.Command(bin, args...).Start()
	}
}
