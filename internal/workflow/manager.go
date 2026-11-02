// Package workflow manages reviewed Windows installation and maintenance jobs.
// A preview is never an execution request. Every execution consumes an expiring
// server-side plan and records its outcome separately from engine process state.
package workflow

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Yunushan/accessweaver/internal/logfile"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/nativeargs"
	"github.com/Yunushan/accessweaver/internal/nativepath"
	"github.com/Yunushan/accessweaver/internal/profile"
)

//go:embed windows.ps1
var scripts embed.FS

type Request struct {
	Action                string   `json:"action"`
	Engine                string   `json:"engine,omitempty"`
	Mode                  string   `json:"mode,omitempty"`
	ProfileID             string   `json:"profileId,omitempty"`
	ConfigPath            string   `json:"configPath,omitempty"`
	BundlePath            string   `json:"bundlePath,omitempty"`
	Applications          []string `json:"applications,omitempty"`
	Browsers              bool     `json:"browsers"`
	Refresh               bool     `json:"refresh"`
	DNS                   string   `json:"dns,omitempty"`
	Scan                  string   `json:"scan,omitempty"`
	Targets               []string `json:"targets,omitempty"`
	Domains               []string `json:"domains,omitempty"`
	Enabled               bool     `json:"enabled"`
	Clean                 bool     `json:"clean"`
	Args                  []string `json:"args,omitempty"`
	DownloadURL           string   `json:"downloadUrl,omitempty"`
	SHA256                string   `json:"sha256,omitempty"`
	AcceptCloudflareTerms bool     `json:"acceptCloudflareTerms"`
	JournalID             string   `json:"journalId,omitempty"`
}

type Plan struct {
	RequiresAdministrator bool      `json:"requiresAdministrator"`
	ID                    string    `json:"id"`
	Request               Request   `json:"request"`
	Steps                 []string  `json:"steps"`
	Issues                []string  `json:"issues"`
	Warnings              []string  `json:"warnings"`
	Ready                 bool      `json:"ready"`
	ExpiresAt             time.Time `json:"expiresAt"`
}

type Job struct {
	ID         string          `json:"id"`
	Action     string          `json:"action"`
	State      string          `json:"state"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt time.Time       `json:"finishedAt,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// Summary reads only status metadata, without copying a potentially large result.
type Summary struct {
	Action        string `json:"action,omitempty"`
	State         string `json:"state"`
	ErrorPresent  bool   `json:"errorPresent"`
	ResultPresent bool   `json:"resultPresent"`
}

func (m *Manager) Summary() Summary {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Summary{Action: m.job.Action, State: m.job.State, ErrorPresent: m.job.Error != "", ResultPresent: len(m.job.Result) > 0}
}

type Operation struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Steps []string `json:"steps"`
}

func Catalog() []Operation {
	return []Operation{
		{"discover", "Inspect installed tools, services and conflicts", []string{"Inspect executable locations, Windows services, network adapters and Discord variants without changing them"}},
		{"download", "Download an official component", []string{"Download an allowlisted upstream asset", "Check the required SHA-256 before using it", "Stage the verified artifact in protected component storage"}},
		{"install", "Install an access method", []string{"Check administrator rights and dependencies; stage components", "Generate application routing and optional wgcf configuration", "Install and verify requested services and firewall rules", "Apply optional DNS and periodic refresh settings"}},
		{"config", "Generate WireSock application configuration", []string{"Register and generate with wgcf if no configuration was supplied", "Compile default, browser and custom application rules into a private .conf file"}},
		{"connect", "Connect an installed WireSock profile", []string{"Verify installed vendor services", "Import the managed profile, connect and inspect vendor status"}},
		{"disconnect", "Disconnect a managed WireSock profile", []string{"Disconnect the managed profile through the product CLI"}},
		{"scan", "Find a Zapret strategy", []string{"Run upstream blockcheck at the requested scan level", "Save the complete output and detected strategies for review"}},
		{"auto-install", "Find and install a Zapret strategy", []string{"Run blockcheck at the selected scan level", "Select a reported common strategy, preferring HTTPS", "Install it as a managed service and retain the complete scan evidence"}},
		{"hostlist", "Save or toggle a live hostlist", []string{"Validate domain names", "Atomically replace the active and preserved lists for the selected managed engine"}},
		{"dns", "Configure encrypted DNS", []string{"Snapshot adapter DNS and native DoH settings before changing them", "Configure DNSCrypt or native Windows DoH", "Verify the selected resolver responds"}},
		{"dns-restore", "Restore saved DNS settings", []string{"Restore the original adapter DNS and DoH snapshot"}},
		{"refresh", "Configure periodic WireSock reconnect", []string{"Create or remove the AccessWeaver scheduled reconnect task"}},
		{"remove", "Remove a managed access method", []string{"Stop dependent services before removing owned services and firewall rules", "Restore owned drover files and remove the owned refresh task where applicable"}},
		{"vendor-uninstall", "Uninstall the WireSock vendor product", []string{"Remove the managed WireSock profile and reconnect task", "Run the registered, publisher-verified vendor uninstaller", "Verify removal or report that a reboot is required"}},
		{"remove-all", "Remove all managed methods", []string{"Remove owned proxy services before packet engines and tunnel configuration", "Restore DNS and owned application files", "Keep unrelated services and vendor products intact"}},
		{"app-install", "Install Discord, PTB or SplitCord", []string{"Obtain an official installer", "Run it for the interactive user and verify installation"}},
		{"app-start", "Start an installed Discord variant", []string{"Find and start the selected application in the interactive user session"}},
		{"app-remove", "Uninstall a Discord variant", []string{"Close only the selected application's processes", "Run its registered or Squirrel uninstaller and verify removal"}},
		{"app-repair", "Repair Discord", []string{"Unavailable until user application maintenance and administrative proxy/DLL changes use a privilege-separated broker"}},
		{"updates", "Check for a newer AccessWeaver release", []string{"Read the official project's GitHub release metadata; do not install anything"}},
		{"uninstall", "Undo AccessWeaver system changes", []string{"Remove AccessWeaver-owned services, tasks and firewall rules", "Restore DNS and application-file backups", "Remove the registered AccessWeaver installation when present"}},
		{"recover", "Recover an interrupted operation", []string{"Read the selected protected recovery journal", "Validate ownership and file hashes before restoring backed-up files and removing newly created resources"}},
		{"choose-folder", "Choose an application folder", []string{"Open the native folder chooser; no system settings are changed"}},
	}
}

type Manager struct {
	startMu      sync.Mutex
	guard        *managed.Guard
	mu           sync.Mutex
	root         string
	plans        map[string]Plan
	job          Job
	cancel       context.CancelFunc
	done         chan struct{}
	closing      bool
	execute      func(context.Context, string, Request) (json.RawMessage, error)
	platform     string
	requireAdmin func() error
}

func New(root string) *Manager { return NewWithGuard(root, managed.NewGuard(nil)) }
func NewWithGuard(root string, guard *managed.Guard) *Manager {
	return &Manager{guard: guard, root: filepath.Join(root, "workflows"), plans: map[string]Plan{}, execute: execute, platform: runtime.GOOS, requireAdmin: requireAdministrator}
}

func (m *Manager) Preview(r Request) (Plan, error) {
	p := Plan{RequiresAdministrator: requiresAdministrator(r.Action), Request: r, Steps: []string{}, Issues: []string{}, Warnings: []string{}, ExpiresAt: time.Now().Add(10 * time.Minute).UTC()}
	found := false
	for _, op := range Catalog() {
		if op.ID == r.Action {
			p.Steps = op.Steps
			found = true
			break
		}
	}
	if !found {
		return p, errors.New("unknown workflow action")
	}
	if err := r.Validate(); err != nil {
		return p, err
	}
	if _, err := workflowPermission(m.guard, r); err != nil {
		p.Issues = append(p.Issues, err.Error())
	}
	if r.Action == "install" {
		p.Steps = installationSteps(r)
	}
	if m.platform != "windows" {
		p.Issues = append(p.Issues, "Windows system workflows require a Windows host")
	}
	if m.platform == "windows" && p.RequiresAdministrator {
		if err := m.checkAdministrativeAccess(); err != nil {
			p.Issues = append(p.Issues, err.Error())
		}
	}
	if r.Action == "app-repair" {
		p.Issues = append(p.Issues, "Combined Discord repair requires a privilege-separated broker and is unavailable. Run application install/remove as your normal desktop user and manage the proxy separately.")
	}
	if r.Action == "app-install" || r.Action == "app-remove" {
		p.Warnings = append(p.Warnings, "Run this application operation as the signed-in desktop user without administrator rights. Application installers and uninstallers must never inherit an elevated token.")
	}
	if (r.Action == "config" || (r.Action == "install" && r.Engine == "wiresock")) && r.ConfigPath == "" && !r.AcceptCloudflareTerms {
		p.Issues = append(p.Issues, "Generating a new WARP account requires accepting Cloudflare's terms; otherwise provide an existing configPath")
	}
	if r.Action != "discover" && r.Action != "updates" && r.Action != "choose-folder" && r.Action != "app-start" {
		p.Warnings = append(p.Warnings, "This operation can change Windows services, network settings or application files. Review its inputs and keep the recovery journal.")
	}
	if r.Action == "config" || r.Action == "install" && r.Engine == "wiresock" {
		p.Warnings = append(p.Warnings, "Generating WARP credentials uses wgcf and Cloudflare's service. Existing configPath avoids registration. Vendor terms apply.")
	}
	if r.Action == "app-remove" || r.Action == "app-repair" || r.Clean {
		p.Warnings = append(p.Warnings, "Application removal or repair can sign you out. Repair preserves cache in the private recovery directory.")
	}
	if r.Action == "vendor-uninstall" {
		p.Warnings = append(p.Warnings, "Uninstalling the selected WireSock product can remove independently created profiles and vendor services. Back up profiles you need before applying this operation.")
	}
	if r.Action == "remove-all" || r.Action == "uninstall" || r.Action == "remove" && (r.Engine == "drover" || r.Engine == "byedpi") {
		p.Warnings = append(p.Warnings, "Restoring managed Discord DLL files closes Discord if it is running.")
	}
	if r.Action == "install" && r.Engine == "wiresock" && r.Mode == "standard" {
		p.Warnings = append(p.Warnings, "Standard setup also installs ByeDPI and Discord drover files. Alternative mode installs only WireSock.")
	}
	p.Ready = len(p.Issues) == 0
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return p, err
	}
	p.ID = hex.EncodeToString(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, old := range m.plans {
		if time.Now().After(old.ExpiresAt) {
			delete(m.plans, id)
		}
	}
	if len(m.plans) >= 64 {
		return p, errors.New("too many unconsumed workflow plans")
	}
	// Detach caller-owned slices before retaining the reviewed request.
	encoded, _ := json.Marshal(p)
	var stored Plan
	_ = json.Unmarshal(encoded, &stored)
	m.plans[p.ID] = stored
	return p, nil
}

func (r Request) Validate() error {
	if (r.Action == "app-install" || r.Action == "app-remove" || r.Action == "app-start") && r.DNS != "" && r.DNS != "unchanged" {
		return errors.New("configure system DNS separately from user application operations")
	}
	if len(r.Args) > 128 || len(r.Applications) > 100 || len(r.Domains) > 4096 || len(r.Targets) > 32 {
		return errors.New("workflow list limit exceeded")
	}
	for _, v := range append(append(append([]string{r.ConfigPath, r.BundlePath, r.DownloadURL}, r.Args...), r.Applications...), r.Domains...) {
		if len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("invalid workflow argument")
		}
	}
	for _, d := range r.Domains {
		if err := profile.ValidateDomain(d); err != nil {
			return err
		}
	}
	for _, host := range r.Targets {
		if err := profile.ValidateHost(host); err != nil {
			return err
		}
		if host == "" {
			return errors.New("scan target cannot be empty")
		}
	}
	for _, a := range r.Applications {
		if strings.TrimSpace(a) == "" || strings.ContainsAny(a, ",;\"") {
			return errors.New("application names cannot contain commas, semicolons or quotes")
		}
	}
	allowed := func(v string, list ...string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	if !allowed(r.Engine, "", "wiresock", "byedpi", "zapret", "zapret2", "goodbyedpi", "dnscrypt", "proxifyre", "windivert", "drover", "discord", "discord-ptb", "splitcord", "wgcf", "ndisapi", "vcredist") {
		return errors.New("unknown workflow component")
	}
	components := map[string][]string{
		"vendor-uninstall": {"wiresock"},
		"install":          {"wiresock", "byedpi", "zapret", "zapret2", "goodbyedpi", "dnscrypt", "ndisapi", "vcredist"},
		"remove":           {"wiresock", "byedpi", "zapret", "zapret2", "goodbyedpi", "dnscrypt", "proxifyre", "windivert", "drover"},
		"hostlist":         {"zapret", "zapret2", "goodbyedpi"},
		"app-install":      {"discord", "discord-ptb", "splitcord"},
		"app-start":        {"discord", "discord-ptb", "splitcord"},
		"app-remove":       {"discord", "discord-ptb", "splitcord"},
		"app-repair":       {"discord"},
	}
	if choices, ok := components[r.Action]; ok && !allowed(r.Engine, choices...) {
		return errors.New("component is not supported for this operation")
	}
	if !allowed(r.Mode, "", "standard", "alternative", "custom", "split", "dll", "service", "once") {
		return errors.New("unknown installation mode")
	}
	if r.Action == "install" && r.Mode != "" {
		switch r.Engine {
		case "wiresock":
			if !allowed(r.Mode, "standard", "alternative", "custom") {
				return errors.New("WireSock setup mode must be standard, alternative or custom")
			}
		case "byedpi":
			if !allowed(r.Mode, "split", "dll", "service", "once") {
				return errors.New("ByeDPI setup mode must be split, dll, service or once")
			}
		case "zapret", "zapret2", "goodbyedpi":
			if !allowed(r.Mode, "service", "once") {
				return errors.New("packet engine setup mode must be service or once")
			}
		}
	}
	if r.Action == "install" && r.Engine == "byedpi" {
		if err := nativeargs.ValidateByeDPIInstall(r.Args); err != nil {
			return err
		}
	}
	if r.Action == "install" && (r.Engine == "zapret" || r.Engine == "zapret2" || r.Engine == "goodbyedpi") {
		for _, arg := range r.Args {
			if strings.HasPrefix(arg, "--hostlist") || strings.HasPrefix(arg, "--blacklist") {
				return errors.New("system setup manages its own hostlist; edit domains here or use the foreground profile runner for native hostlist arguments")
			}
		}
	}
	if !allowed(r.DNS, "", "unchanged", "doh", "dnscrypt") {
		return errors.New("unknown DNS method")
	}
	if !allowed(r.Scan, "", "quick", "standard", "full") {
		return errors.New("unknown scan level")
	}
	if r.ProfileID != "" && !profileID(r.ProfileID) {
		return errors.New("invalid managed profile ID")
	}
	if (r.Action == "install" || r.Action == "remove" || r.Action == "download" || r.Action == "scan" || r.Action == "hostlist" || strings.HasPrefix(r.Action, "app-")) && r.Engine == "" {
		return errors.New("choose a component or application")
	}
	if r.Action == "dns" && (r.DNS == "" || r.DNS == "unchanged") {
		return errors.New("choose Windows DoH or DNSCrypt")
	}
	if len(r.Args) > 0 && (r.Action != "install" || !allowed(r.Engine, "byedpi", "zapret", "zapret2", "goodbyedpi")) {
		return errors.New("native arguments apply only to ByeDPI and packet-engine installation")
	}
	if r.Action == "install" && r.Engine == "dnscrypt" && r.DNS == "doh" {
		return errors.New("DNSCrypt installation cannot select Windows DoH")
	}
	if r.Action == "install" && r.Refresh && r.Engine != "wiresock" {
		return errors.New("periodic reconnect applies only to WireSock")
	}
	if r.Action == "install" && (r.Browsers || len(r.Applications) > 0) && !allowed(r.Engine, "byedpi", "wiresock") {
		return errors.New("application selection requires WireSock or ByeDPI interception")
	}
	if r.Action == "download" {
		if !strings.HasPrefix(r.DownloadURL, "https://") || len(r.SHA256) != 64 {
			return errors.New("official HTTPS download URL and SHA-256 are required")
		}
		if _, err := hex.DecodeString(r.SHA256); err != nil {
			return errors.New("invalid SHA-256")
		}
	}
	if (r.Action == "scan" || r.Action == "auto-install") && (r.Engine != "zapret" && r.Engine != "zapret2") {
		return errors.New("strategy scanning supports Zapret and Zapret2")
	}
	if r.Action == "recover" {
		name := r.JournalID
		if len(name) != 46 || !strings.HasPrefix(name, "workflow-") || !strings.HasSuffix(name, ".json") {
			return errors.New("choose a workflow-<32 hexadecimal digits>.json recovery journal")
		}
		if _, err := hex.DecodeString(name[9:41]); err != nil {
			return errors.New("invalid recovery journal name")
		}
	}
	return nil
}
func installationSteps(r Request) []string {
	steps := []string{}
	if r.Engine != "dnscrypt" && r.DNS != "" && r.DNS != "unchanged" {
		steps = append(steps, "Save original DNS settings and configure the selected encrypted resolver")
	}
	switch r.Engine {
	case "wiresock":
		steps = append(steps, "Install the official WireSock product if needed")
		if r.ConfigPath != "" {
			steps = append(steps, "Create a private copy of the supplied tunnel configuration with the selected application rules")
		} else {
			steps = append(steps, "Register with wgcf after accepting Cloudflare terms, then generate private application configuration")
		}
		steps = append(steps, "Import a uniquely named managed profile and connect it")
		if r.Mode == "standard" {
			steps = append(steps, "Install the ByeDPI service and Discord drover files with original-file backups")
		}
		if r.Refresh {
			steps = append(steps, "Register the five-minute reconnect task")
		}
	case "byedpi":
		steps = append(steps, "Stage ByeDPI and listen on the local SOCKS endpoint 127.0.0.1:1080")
		if r.Mode == "once" {
			steps = append(steps, "Run until the operation is cancelled")
		} else {
			steps = append(steps, "Install an automatic Windows service and its firewall rules")
		}
		if r.Mode == "dll" {
			steps = append(steps, "Close Discord and deploy drover files with original-file backups")
		}
		if r.Mode == "split" || r.Mode == "" {
			steps = append(steps, "Install Windows Packet Filter and runtime prerequisites if needed, then start ProxiFyre for the selected applications")
		}
	case "zapret", "zapret2", "goodbyedpi":
		steps = append(steps, "Stage the packet engine, its matching assets and WinDivert driver", "Save the requested active and preserved hostlists")
		if r.Mode == "once" {
			steps = append(steps, "Run the selected strategy until cancellation")
		} else {
			steps = append(steps, "Install and start the selected strategy as an automatic Windows service")
		}
	case "dnscrypt":
		steps = append(steps, "Save original adapter DNS settings", "Install the DNSCrypt service, select local resolver addresses and verify readiness")
	default:
		steps = append(steps, "Verify the official prerequisite installer and run it without an automatic reboot")
	}
	return steps
}
func profileID(id string) bool {
	if len(id) < 2 || len(id) > 63 || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func (m *Manager) Start(id string) (Job, error) {
	m.startMu.Lock()
	defer m.startMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return Job{}, errors.New("system workflow manager is shutting down")
	}
	if m.job.State == "running" {
		return Job{}, errors.New("a system workflow is already running")
	}
	p, ok := m.plans[id]
	if !ok || time.Now().After(p.ExpiresAt) {
		return Job{}, errors.New("workflow plan expired; preview again")
	}
	if !p.Ready {
		return Job{}, errors.New(strings.Join(p.Issues, "; "))
	}
	// Native provenance checks must not hold the status mutex while doing I/O.
	m.mu.Unlock()
	permission, policyErr := workflowPermission(m.guard, p.Request)
	var ctx context.Context
	var cancel context.CancelFunc
	if policyErr == nil {
		base, baseCancel := context.WithTimeout(context.Background(), 90*time.Minute)
		var monitorCancel context.CancelFunc
		ctx, monitorCancel, policyErr = permission.Authorization.Context(base)
		cancel = func() {
			baseCancel()
			if monitorCancel != nil {
				monitorCancel()
			}
		}
	}
	started := false
	defer func() {
		if !started && cancel != nil {
			cancel()
		}
	}()
	m.mu.Lock()
	if policyErr != nil {
		return Job{}, policyErr
	}
	if m.closing {
		return Job{}, errors.New("system workflow manager is shutting down")
	}
	if m.job.State == "running" {
		return Job{}, errors.New("a system workflow is already running")
	}
	if _, ok := m.plans[id]; !ok || time.Now().After(p.ExpiresAt) {
		return Job{}, errors.New("workflow plan expired; preview again")
	}
	if p.RequiresAdministrator {
		if err := m.checkAdministrativeAccess(); err != nil {
			return Job{}, err
		}
	}
	delete(m.plans, id)
	if err := os.MkdirAll(m.root, 0700); err != nil {
		return Job{}, err
	}
	m.cancel = cancel
	m.job = Job{ID: id, Action: p.Request.Action, State: "running", StartedAt: time.Now().UTC()}
	if err := m.saveLocked(); err != nil {
		cancel()
		m.job.State = "failed"
		return Job{}, err
	}
	done := make(chan struct{})
	m.done = done
	started = true
	go func() {
		defer close(done)
		result, err := m.execute(ctx, filepath.Join(m.root, id), p.Request)
		if cause := context.Cause(ctx); managed.IsPolicyError(cause) {
			err = errors.Join(cause, err)
		}
		if resultErr := validateResult(result); resultErr != nil {
			result = nil
			err = errors.Join(err, resultErr)
		}
		cancel()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.job.Result = result
		m.job.FinishedAt = time.Now().UTC()
		m.job.State = "succeeded"
		if err != nil {
			m.job.State = "failed"
			m.job.Error = err.Error()
		}
		if e := m.saveLocked(); e != nil {
			m.job.State = "failed"
			m.job.Error += "; persist result: " + e.Error()
		}
	}()
	return m.job, nil
}
func (m *Manager) saveLocked() error {
	b, e := json.MarshalIndent(m.job, "", "  ")
	if e != nil {
		return e
	}
	return profile.AtomicWrite(filepath.Join(m.root, m.job.ID+".json"), b)
}
func (m *Manager) Snapshot() Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.job
	j.Result = append(json.RawMessage(nil), j.Result...)
	return j
}
func (m *Manager) Cancel() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
}

// Shutdown rejects new jobs and waits for cancellation and durable outcome recording.
// A timeout does not claim that vendor cleanup or rollback completed.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closing = true
	if m.cancel != nil {
		m.cancel()
	}
	done := m.done
	m.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func execute(ctx context.Context, dir string, r Request) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		return nil, errors.New("Windows required")
	}
	permission, err := workflowPermission(managed.NewGuard(nil), r)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	script, _ := scripts.ReadFile("windows.ps1")
	scriptPath := filepath.Join(dir, "workflow.ps1")
	if err := profile.AtomicWrite(scriptPath, script); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	hook, _ := presetFiles.ReadFile("presets/00-accessweaver-isp.sh")
	input := struct {
		Request        Request                `json:"request"`
		Controller     string                 `json:"controller"`
		ResultPath     string                 `json:"resultPath"`
		ISPHook        string                 `json:"ispHook"`
		ManagedPolicy  bool                   `json:"managedPolicy"`
		AllowDownloads bool                   `json:"allowDownloads"`
		Downloads      []managed.DownloadRule `json:"downloads"`
	}{r, executable, filepath.Join(dir, "result.json"), string(hook), permission.Managed, permission.AllowDownloads, permission.Downloads}
	b, _ := json.Marshal(input)
	requestPath := filepath.Join(dir, "request.json")
	if err := profile.AtomicWrite(requestPath, b); err != nil {
		return nil, err
	}
	// Execute the embedded program and the exact retained request through stdin.
	// Editable debug snapshots in the user's configuration directory must not be
	// reread as privileged code or as a different request after launch review.
	program := strings.Replace(string(script), "param([Parameter(Mandatory=$true)][string]$RequestPath)", "param()", 1)
	program = strings.Replace(program, "$inputData = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json", "$inputData = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+base64.StdEncoding.EncodeToString(b)+"')) | ConvertFrom-Json", 1)
	systemDirectory, err := nativepath.SystemDirectory()
	if err != nil {
		return nil, err
	}
	powershell := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	environment, err := nativepath.ProcessEnvironment()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, powershell, "-NoProfile", "-NonInteractive", "-STA", "-ExecutionPolicy", "Bypass", "-Command", "$source=[Console]::In.ReadToEnd(); & ([scriptblock]::Create($source))")
	cmd.Env = environment
	cmd.Dir = systemDirectory
	cmd.Stdin = strings.NewReader(program)
	cmd.WaitDelay = 2 * time.Second
	configureCommand(cmd)
	log, err := logfile.Open(filepath.Join(dir, "process.log"), 4<<20, 2)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	cmd.Stdout = log
	cmd.Stderr = log
	err = cmd.Run()
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			err = errors.Join(err, contextErr)
		}
	}
	result, readErr := readWorkflowFile(input.ResultPath, maxResultBytes)
	if readErr != nil {
		return nil, errors.Join(err, fmt.Errorf("read workflow result: %w", readErr))
	}
	if resultErr := validateResult(result); resultErr != nil {
		return nil, errors.Join(err, resultErr)
	}
	if err != nil {
		var outcome struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(result, &outcome) == nil && outcome.Error != "" {
			return result, fmt.Errorf("Windows workflow failed: %s: %w", outcome.Error, err)
		}
		return result, fmt.Errorf("Windows workflow failed (%w); inspect process.log and the protected recovery journal", err)
	}
	var outcome struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if e := json.Unmarshal(result, &outcome); e != nil {
		return nil, e
	}
	if !outcome.OK {
		return result, errors.New(outcome.Error)
	}
	return result, nil
}

// Keep the few non-administrative operations explicit. New machine operations
// default to requiring an administrative process, independently of UI consent.
func requiresAdministrator(action string) bool {
	switch action {
	case "discover", "updates", "choose-folder", "app-install", "app-start", "app-remove":
		return false
	default:
		return true
	}
}
func (m *Manager) checkAdministrativeAccess() error {
	if m.requireAdmin == nil {
		return errors.New("cannot determine administrator access; use a separately elevated system apply CLI")
	}
	return m.requireAdmin()
}
