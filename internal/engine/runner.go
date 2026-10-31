package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Yunushan/accessweaver/internal/profile"
)

type Snapshot struct {
	State     string    `json:"state"`
	ProfileID string    `json:"profileId,omitempty"`
	Engine    string    `json:"engine,omitempty"`
	PID       int       `json:"pid,omitempty"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	LastError string    `json:"lastError,omitempty"`
	Log       []string  `json:"log"`
}

type Manager struct {
	opMu     sync.Mutex // Serializes prepare/start/stop, including generated files.
	mu       sync.Mutex
	cmd      *exec.Cmd
	done     chan struct{}
	state    Snapshot
	log      []string
	root     string
	stopping bool
}

func NewManager(root string) *Manager {
	return &Manager{root: root, state: Snapshot{State: "stopped", Log: []string{}}, log: make([]string, 0, 150)}
}
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state
	s.Log = append([]string{}, m.log...)
	return s
}
func (m *Manager) addLog(line string) { m.mu.Lock(); defer m.mu.Unlock(); m.addLogLocked(line) }
func (m *Manager) addLogLocked(line string) {
	// Child output is untrusted text. Strip terminal control characters before
	// showing it in either the browser or a console.
	line = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		if r == 127 {
			return -1
		}
		return r
	}, line)
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if len(line) > 2000 {
		line = line[:2000] + "…"
	}
	m.log = append(m.log, time.Now().Format("15:04:05")+"  "+line)
	if len(m.log) > 150 {
		m.log = append([]string(nil), m.log[len(m.log)-150:]...)
	}
}

type logWriter struct{ m *Manager }

func (w logWriter) Write(b []byte) (int, error) {
	s := string(b)
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			w.m.addLog(line)
		}
	}
	return len(b), nil
}

func (m *Manager) Start(p profile.Profile) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	if m.cmd != nil {
		m.mu.Unlock()
		return errors.New("another engine is running; stop it before starting a new one")
	}
	m.mu.Unlock()
	bin, args, err := Prepare(p, m.root)
	if err != nil {
		return err
	}
	// External executables are only started following an explicit user action.
	cmd := exec.Command(bin, args...)
	cmd.Dir = filepath.Dir(bin)
	cmd.WaitDelay = 2 * time.Second
	configureProcess(cmd)
	cmd.Stdout = logWriter{m}
	cmd.Stderr = logWriter{m}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		return errors.New("another engine started concurrently")
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("engine start failed: %w", err)
	}
	m.cmd = cmd
	m.stopping = false
	m.done = make(chan struct{})
	m.state = Snapshot{State: "running", ProfileID: p.ID, Engine: p.Engine, PID: cmd.Process.Pid, StartedAt: time.Now().UTC()}
	m.log = nil
	m.addLogLocked("Engine process launched; service/network connectivity is NOT yet verified")
	done := m.done
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
			m.state.State = "stopped"
			m.state.PID = 0
			if err != nil && !m.stopping {
				m.state.State = "error"
				m.state.LastError = err.Error()
			}
		}
		if err != nil && !m.stopping {
			m.addLogLocked("Engine process exited: " + err.Error())
		} else {
			m.addLogLocked("Engine process exited normally")
		}
		close(done)
		m.mu.Unlock()
	}()
	return nil
}
func (m *Manager) Stop() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	cmd := m.cmd
	done := m.done
	if cmd != nil {
		m.stopping = true
		m.state.State = "stopping"
	}
	m.mu.Unlock()
	if cmd == nil {
		return nil
	}
	if err := interruptProcess(cmd.Process); err != nil {
		if err = killProcess(cmd.Process); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}
	select {
	case <-done:
		return nil
	case <-time.After(3 * time.Second):
		_ = killProcess(cmd.Process)
		select {
		case <-done:
			return nil
		case <-time.After(time.Second):
			return errors.New("engine did not exit within timeout")
		}
	}
}
func (m *Manager) Shutdown(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- m.Stop() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
