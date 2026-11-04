package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/profile"
)

var (
	errAuditRunConsent   = errors.New("recorded engine run requires explicit metadata-only consent")
	errAuditRunProfile   = errors.New("recorded engine profile must be a valid bounded profile JSON file")
	errAuditRunAdmission = errors.New("recorded engine admission unavailable; no engine was launched")
	errAuditRunPreview   = errors.New("recorded engine prerequisites or managed authorization are unavailable; no engine was launched")
	errAuditRunOutput    = errors.New("recorded engine outputs must be available, separate and must not alias known protected inputs")
)

func recordedRunPaths(args []string) (map[string]string, error) {
	paths, err := auditPaths(args, "run", "--directory", "--from", "--to", "--profile", "--consent")
	if err != nil {
		return nil, err
	}
	if paths["--consent"] != "metadata-only" {
		return nil, errAuditRunConsent
	}
	return paths, nil
}

// Checkpoints alone go to observations (stdout); the fixed launch notice goes
// to notice (stderr). Callers must keep forwarded pipe/writer destinations
// separate and protect arbitrary upstream inputs that the launch plan cannot name.
func auditRunCommand(args []string, observations, notice io.Writer) (failure error) {
	paths, err := recordedRunPaths(args)
	if err != nil {
		return err
	}
	if !audit.LocalRecordingSupported() {
		return audit.ErrLocalStorageUnsupported
	}
	if observations == nil || notice == nil {
		return errAuditRunOutput
	}
	restoreOutput := observeAuditOutputPipes()
	defer restoreOutput()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	inputCtx, cancelInput := context.WithTimeout(ctx, 15*time.Second)
	defer cancelInput()
	decode := func(path string) (audit.Checkpoint, error) {
		data, err := readAuditInput(inputCtx, path, audit.MaxCheckpointBytes)
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
	data, err := readAuditInput(inputCtx, paths["--profile"], 1<<20)
	if err != nil {
		return err
	}
	p, err := profile.Decode(bytes.NewReader(data))
	clear(data)
	if err != nil {
		return errAuditRunProfile
	}
	root, err := profile.DefaultRoot()
	if err != nil {
		return errAuditRunAdmission
	}
	if override := os.Getenv("ACCESSWEAVER_HOME"); override != "" {
		root = override
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return errAuditRunAdmission
	}
	controllerPath := filepath.Join(root, ".controller.lock")
	required := []string{paths["--from"], paths["--to"], paths["--profile"], filepath.Join(paths["--directory"], "events.journal"), filepath.Join(paths["--directory"], ".actor-key")}
	optional := []string{"/etc/accessweaver/installation.json", "/etc/accessweaver/acceptance.json", "/etc/.accessweaver-policy.lock", controllerPath, filepath.Join(root, ".profiles.lock")}
	if p.ConfigPath != "" {
		optional = append(optional, p.ConfigPath)
	}
	if err := checkRecordedEngineOutputs(observations, notice, required, optional); err != nil {
		return err
	}
	journal, err := audit.OpenLocalJournal(inputCtx, paths["--directory"], from, to)
	if err != nil {
		return err
	}
	var controller io.Closer
	defer func() {
		if err := closeRecordedEngineScope(journal, controller); err != nil {
			failure = errors.Join(failure, err)
		}
	}()
	if inputCtx.Err() != nil {
		return errAuditRunAdmission
	}
	// Open only the existing controller scope. Do not seed, import or save
	// profile inventory as part of preparing an explicit recorded run.
	if _, err := profile.NewStore(root); err != nil {
		return errAuditRunAdmission
	}
	lock, err := filelock.TryAcquire(controllerPath)
	if err != nil {
		return errAuditRunAdmission
	}
	controller = lock
	manager := engine.NewManager(root)
	// Preview is read-only. Prepare/StartTracked may write generated inputs,
	// so only the borrowed producer can invoke it after observed durable intent.
	plan, err := manager.Preview(p)
	if err != nil || !plan.Ready || plan.Binary == "" {
		return errAuditRunPreview
	}
	required = append(required, controllerPath, plan.Binary)
	if p.ConfigPath != "" {
		required = append(required, p.ConfigPath)
	}
	optional = append(optional, plan.GeneratedFiles...)
	// Compare under controller ownership, including newly created coordination
	// files and the currently resolved executable/config/generated inputs.
	if err := checkRecordedEngineOutputs(observations, notice, required, optional); err != nil {
		return err
	}
	if inputCtx.Err() != nil {
		return errAuditRunAdmission
	}
	cancelInput() // The separate admission/input budget is not the engine lifetime.
	return executeRecordedEngine(ctx, journal, from, to, observations, notice, func() (foregroundEngineRun, error) {
		run, err := manager.StartTracked(p)
		if err != nil {
			return nil, err
		}
		// This concrete, in-process manager guarantees a valid accepted handle.
		// HTTP/JSON input cannot supply a launch implementation or an audit capability.
		return run, nil
	}, manager.Stop)
}

func checkRecordedEngineOutputs(observations, notice io.Writer, required, optional []string) error {
	if observations == nil || notice == nil {
		return errAuditRunOutput
	}
	if err := checkAuditUIOutputs(observations, notice, required); err != nil {
		return errAuditRunOutput
	}
	for _, destination := range []io.Writer{observations, notice} {
		if err := checkRecordedPolicyOutput(destination, required, optional); err != nil {
			return errAuditRunOutput
		}
	}
	return nil
}

// The outer command is the sole owner. Never release controller exclusion while
// journal Close is still blocked, and never retry a failed Close to erase it.
func closeRecordedEngineScope(journal, controller io.Closer) error {
	var failure error
	if journal != nil && journal.Close() != nil {
		failure = audit.ErrRecordedUncertain
	}
	if controller != nil && controller.Close() != nil {
		failure = audit.ErrRecordedUncertain
	}
	return failure
}
