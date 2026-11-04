package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/uiaccess"
	"github.com/Yunushan/accessweaver/web"
)

// Stdout contains canonical checkpoints only. Startup information/private
// launcher location go to stderr, which must also be retained privately.
func auditUICommand(args []string, out, info io.Writer) (failure error) {
	paths, err := auditPaths(args, "ui", "--directory", "--from", "--to")
	if err != nil {
		return err
	}
	if !audit.LocalRecordingSupported() {
		return audit.ErrLocalStorageUnsupported
	}
	if err := uiaccess.RequireUnelevated(); err != nil {
		return err
	}
	restoreOutputPipes := observeAuditOutputPipes()
	defer restoreOutputPipes()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	inputCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	inputs := &auditInputSession{}
	decode := func(path string) (audit.Checkpoint, error) {
		data, err := inputs.read(inputCtx, path, audit.MaxCheckpointBytes)
		if err != nil {
			return audit.Checkpoint{}, err
		}
		return audit.DecodeCheckpoint(data)
	}
	from, err := decode(paths["--from"])
	if err != nil {
		return err
	}
	to, err := decode(paths["--to"])
	if err != nil {
		return err
	}
	// Compare direct regular-file destinations before any checkpoint write. A
	// caller must also prevent wrappers/pipes from forwarding into these inputs.
	if err := checkAuditOutputAliases(inputCtx, []io.Writer{out, info}, inputs.bindings, auditStorageReferences(paths["--directory"])); err != nil {
		return err
	}
	journal, err := audit.OpenLocalJournal(inputCtx, paths["--directory"], from, to)
	if err != nil {
		return err
	}
	recorder, err := audit.NewRecorder(inputCtx, journal, from, to, out)
	if err != nil {
		_ = journal.Close()
		return err
	}
	var controller *filelock.Lock
	defer func() {
		// Keep controller ownership until every recorded callback has returned,
		// including requests still draining after HTTP shutdown's finite budget.
		if recorder.Close() != nil {
			failure = audit.ErrRecordedUncertain
		}
		if controller != nil && controller.Close() != nil {
			failure = audit.ErrRecordedUncertain
		}
	}()
	if err := inputCtx.Err(); err != nil {
		return err
	}
	cancel()
	root, err := profile.DefaultRoot()
	if err != nil {
		return err
	}
	if override := os.Getenv("ACCESSWEAVER_HOME"); override != "" {
		root = override
	}
	// Opening creates store/lock directories only. It never seeds built-in profiles
	// outside recorded operations. Existing ordinary controllers are excluded.
	store, err := profile.NewStore(root)
	if err != nil {
		return err
	}
	controller, err = filelock.TryAcquire(filepath.Join(root, ".controller.lock"))
	if err != nil {
		return errors.New("controller data directory unavailable; close its other controller before starting audited profile editing")
	}
	server, err := api.NewProfileAudited(store, engine.NewManager(root), web.Assets, recorder)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(info, "Audited profile editing only: engine, workflow, diagnostics and support operations are unavailable. No built-in profiles are seeded."); err != nil {
		return errors.New("desktop startup output unavailable")
	}
	return serveDesktop(ctx, server, info)
}
func checkAuditUIOutputs(out, info io.Writer, inputs []string) error {
	return checkAuditOutputAliases(context.Background(), []io.Writer{out, info}, nil, auditFileReferences(inputs, nil, true))
}
func serveDesktop(ctx context.Context, server *api.Server, info io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	addr, err := server.Serve(ctx)
	if err != nil {
		return err
	}
	// Always wait for shutdown, including startup/launcher/output errors.
	defer func() { cancel(); server.Wait() }()
	launcher, err := uiaccess.New(addr, server.Token)
	if err != nil {
		return err
	}
	defer launcher.Close()
	if _, err := fmt.Fprintf(info, "AccessWeaver is running at %s\nOpen this private launch file in your browser: %s\nLocal interface only. Press Ctrl+C to exit. No external engines started automatically.\n", addr, launcher.URL); err != nil {
		return errors.New("desktop startup output unavailable")
	}
	if os.Getenv("ACCESSWEAVER_NO_BROWSER") != "1" {
		openBrowser(launcher.URL)
	}
	<-ctx.Done()
	return nil
}
