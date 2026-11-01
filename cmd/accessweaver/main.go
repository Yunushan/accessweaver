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
	"time"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/diagnostics"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/filelock"
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
	if args[0] == "managed" {
		return managedCommand(args[1:])
	}
	if args[0] == "ui" {
		if err := uiaccess.RequireUnelevated(); err != nil {
			return err
		}
	}
	root, err := profile.DefaultRoot()
	if err != nil {
		return err
	}
	if env := os.Getenv("ACCESSWEAVER_HOME"); env != "" {
		root = env
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
		apiServer, err := api.New(store, manager, web.Assets)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		addr, err := apiServer.Serve(ctx)
		if err != nil {
			return err
		}
		launcher, err := uiaccess.New(addr, apiServer.Token)
		if err != nil {
			stop()
			apiServer.Wait()
			return err
		}
		defer launcher.Close()
		fmt.Println("AccessWeaver is running at", addr)
		fmt.Println("Open this private launch file in your browser:", launcher.URL)
		fmt.Println("Local interface only. Press Ctrl+C to exit. No external engines started automatically.")
		if os.Getenv("ACCESSWEAVER_NO_BROWSER") != "1" {
			openBrowser(launcher.URL)
		}
		<-ctx.Done()
		apiServer.Wait()
		return nil
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
		p, err := store.Get(args[1])
		if err != nil {
			return err
		}
		plan, err := engine.Preview(p, root)
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
		host := "discord.com"
		if len(args) > 1 {
			host = args[1]
		}
		probe := profile.Probe{Host: host, Port: 443, TLS: true, TimeoutSeconds: 5}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return printJSON(diagnostics.Run(ctx, probe))
	case "run":
		if len(args) < 2 {
			return errors.New("usage: accessweaver run PROFILE_ID")
		}
		p, err := store.Get(args[1])
		if err != nil {
			return err
		}
		manager := engine.NewManager(root)
		if err := manager.Start(p); err != nil {
			return err
		}
		fmt.Println("Process launched. This does not guarantee functional routing or connection.")
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ticker := time.NewTicker(700 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				st := manager.Snapshot()
				if st.State == "error" {
					return fmt.Errorf("engine exited: %s", st.LastError)
				}
				if st.State == "stopped" {
					return nil
				}
			case <-ctx.Done():
				return manager.Stop()
			}
		}
	default:
		return fmt.Errorf("unknown command %q; use help", args[0])
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
  accessweaver doctor [HOST]       Run DNS/TCP/TLS checks
  accessweaver run ID              Explicitly start one engine in foreground
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
