package engine

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/nativeargs"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// LaunchPlan is a read-only explanation. Ready means local prerequisites passed,
// not that a strategy is effective or that packet interception is installed.
type LaunchPlan struct {
	policyError      error
	Engine           string   `json:"engine"`
	Platform         string   `json:"platform"`
	Binary           string   `json:"binary"`
	Args             []string `json:"args"`
	WorkingDirectory string   `json:"workingDirectory"`
	Warnings         []string `json:"warnings"`
	Ready            bool     `json:"ready"`
	Issues           []string `json:"issues"`
	GeneratedFiles   []string `json:"generatedFiles"`
}

func executableBase(path string) string {
	return strings.TrimSuffix(strings.ToLower(filepath.Base(path)), ".exe")
}

func binaryFor(p profile.Profile, d Descriptor) (string, error) {
	bin := strings.TrimSpace(p.Binary)
	names := d.ExecutablesFor(runtime.GOOS)
	if bin == "" {
		for _, name := range names {
			if found, err := exec.LookPath(name); err == nil {
				bin = found
				break
			}
		}
		if bin == "" {
			for _, candidate := range installedCandidates(p.Engine) {
				if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
					bin = candidate
					break
				}
			}
		}
		if bin == "" {
			return "", fmt.Errorf("%s is not installed: set the official executable path", d.Name)
		}
	} else if !filepath.IsAbs(bin) {
		if strings.ContainsAny(bin, "/\\") {
			return "", errors.New("binary must be an absolute path or executable name in PATH")
		}
		found, err := exec.LookPath(bin)
		if err != nil {
			return "", fmt.Errorf("find executable: %w", err)
		}
		bin = found
	}
	bin, err := filepath.Abs(bin)
	if err != nil {
		return "", err
	}
	base := executableBase(bin)
	matched := false
	for _, name := range names {
		if base == name {
			matched = true
			break
		}
	}
	if !matched {
		if p.Engine == "wiresock" && base == "wiresock-connect-cli" {
			return "", errors.New("WireSock Secure Connect 3.x uses the Installation & repair connect/install workflows; this profile adapter targets the SDK foreground client")
		}
		return "", fmt.Errorf("%q is not a %s executable for %s; expected %s", base, d.Name, runtime.GOOS, strings.Join(names, ", "))
	}
	info, err := os.Stat(bin)
	if err != nil {
		return "", fmt.Errorf("read executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("binary must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0 {
		return "", errors.New("binary is not executable; check file permissions")
	}
	if p.SHA256 != "" {
		f, err := os.Open(bin)
		if err != nil {
			return "", err
		}
		digest, err := executableHash(f)
		if err != nil {
			return "", err
		}
		if !strings.EqualFold(digest, p.SHA256) {
			return "", errors.New("executable SHA-256 mismatch; not launched")
		}
	}
	return bin, nil
}

func hasOption(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n || strings.HasPrefix(a, n+"=") {
				return true
			}
		}
	}
	return false
}
func hasPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func usesDomainFiles(engine string) bool {
	return (engine != "zapret" && engine != "zapret2") || runtime.GOOS == "windows"
}

// Preview does not execute external code, write generated files, or probe the network.
// Bad schema is an error; missing engine prerequisites are returned as actionable issues.
func Preview(p profile.Profile, root string) (LaunchPlan, error) {
	return previewWithGuard(p, root, managed.NewGuard(nil))
}
func previewWithGuard(p profile.Profile, root string, guard *managed.Guard) (LaunchPlan, error) {
	plan := LaunchPlan{Engine: p.Engine, Platform: runtime.GOOS, Binary: p.Binary, Args: []string{}, Warnings: []string{}, Issues: []string{}, GeneratedFiles: []string{}}
	if err := p.Validate(); err != nil {
		return plan, err
	}
	d, err := Lookup(p.Engine)
	if err != nil {
		return plan, err
	}
	issue := func(s string) { plan.Issues = append(plan.Issues, s) }
	if !d.Supported(runtime.GOOS) {
		issue(fmt.Sprintf("%s is not supported on %s by this adapter", d.Name, runtime.GOOS))
	}
	if d.Integration != "managed" {
		issue("This engine has an external reference integration; manage its tunnel with the official OS client")
	}
	if len(p.Routing.Applications) > 0 && p.Engine != "wiresock" {
		issue("application routing fields are not implemented by this adapter; configure WireSock applications in its .conf file or use upstream configuration")
	}
	if p.Engine == "wiresock" {
		for _, app := range p.Routing.Applications {
			if strings.ContainsAny(app, ",;\"\r\n") {
				issue("WireSock application names cannot contain commas, semicolons, quotes or newlines")
			}
		}
	}
	if len(p.Routing.IncludeDomains) > 0 && !d.Includes {
		issue("this engine adapter does not support include-domain rules")
	}
	if len(p.Routing.ExcludeDomains) > 0 && !d.Excludes {
		issue("this engine adapter does not support exclusion rules")
	}
	if p.Engine != "zapret" && p.Engine != "zapret2" {
		for _, list := range [][]string{p.Routing.IncludeDomains, p.Routing.ExcludeDomains} {
			for _, domain := range list {
				if strings.HasPrefix(domain, "^") {
					issue("the ^ exact-match syntax is supported only by zapret hostlists")
					break
				}
			}
		}
	}
	bin, binErr := binaryFor(p, d)
	if binErr != nil {
		issue(binErr.Error())
	} else {
		plan.Binary = bin
		plan.WorkingDirectory = filepath.Dir(bin)
	}
	if plan.WorkingDirectory == "" && filepath.IsAbs(p.Binary) {
		plan.WorkingDirectory = filepath.Dir(p.Binary)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return plan, err
	}
	include := filepath.Join(root, "generated", p.ID+"-include.txt")
	exclude := filepath.Join(root, "generated", p.ID+"-exclude.txt")
	if len(p.Routing.IncludeDomains) > 0 && d.Includes && usesDomainFiles(p.Engine) {
		plan.GeneratedFiles = append(plan.GeneratedFiles, include)
	}
	if len(p.Routing.ExcludeDomains) > 0 && d.Excludes && usesDomainFiles(p.Engine) {
		plan.GeneratedFiles = append(plan.GeneratedFiles, exclude)
	}
	adapterProfile := p
	if p.Engine == "wiresock" && len(p.Routing.Applications) > 0 {
		adapterProfile.ConfigPath = filepath.Join(root, "generated", p.ID+"-wiresock.conf")
		plan.GeneratedFiles = append(plan.GeneratedFiles, adapterProfile.ConfigPath)
		plan.Warnings = append(plan.Warnings, "Guided application rules replace AllowedApps/DisallowedApps in a generated configuration copy. The original tunnel configuration is unchanged.")
	}
	args, warnings, argumentIssues := adapterArgs(adapterProfile, executableBase(plan.Binary), include, exclude)
	plan.Args = args
	plan.Warnings = append(plan.Warnings, warnings...)
	plan.Issues = append(plan.Issues, argumentIssues...)
	argumentBytes := len(plan.Binary)
	for _, arg := range args {
		argumentBytes += len(arg) + 3
	}
	limit := 64 * 1024
	if runtime.GOOS == "windows" {
		limit = 24 * 1024
	}
	if argumentBytes > limit {
		issue("generated command exceeds the managed argument-size limit; reduce guided lists or use native hostlist files readable by the engine after privilege dropping")
	}
	if p.ConfigPath != "" {
		if p.Engine != "wiresock" && p.Engine != "sing-box" && p.Engine != "xray" {
			issue("configPath is only supported by WireSock, sing-box and Xray; use native arguments for other engines")
		} else if err := inspectConfig(p); err != nil {
			issue(err.Error())
		}
	}
	if p.SHA256 == "" {
		plan.Warnings = append(plan.Warnings, "Executable identity is not pinned. An expected SHA-256 can be set in this profile; a filename alone does not establish trust.")
	}
	plan.Warnings = append(plan.Warnings, "External engines and their configuration run with this controller's privileges. A launched process does not prove working connectivity.")
	if err := checkLaunchPolicy(guard, p, plan.Binary); err != nil {
		plan.policyError = err
		issue(err.Error())
	}
	plan.Ready = len(plan.Issues) == 0
	return plan, nil
}

func inspectConfig(p profile.Profile) error {
	if !filepath.IsAbs(p.ConfigPath) {
		return errors.New("configPath must be an absolute path to a local file")
	}
	fi, err := os.Stat(p.ConfigPath)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > 4<<20 {
		return errors.New("configuration must be a regular file no larger than 4 MiB")
	}
	f, err := os.Open(p.ConfigPath)
	if err != nil {
		return fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	if p.Engine != "wiresock" {
		return nil
	}
	// WireSock supports shell hooks. Reject them so importing a tunnel does not
	// quietly become a script runner. Never include a line/value in errors (keys).
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, _, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "preup", "postup", "predown", "postdown":
			return errors.New("WireSock configuration contains a command hook (PreUp/PostUp/PreDown/PostDown); remove hooks for managed mode")
		}
	}
	if scanner.Err() != nil {
		return errors.New("could not inspect WireSock configuration")
	}
	return nil
}

func adapterArgs(p profile.Profile, base, include, exclude string) ([]string, []string, []string) {
	args := append([]string{}, p.Args...)
	warnings, issues := []string{}, []string{}
	in, out := len(p.Routing.IncludeDomains) > 0, len(p.Routing.ExcludeDomains) > 0
	if hasOption(args, "--daemon", "--daemonize", "--service", "-D") {
		issues = append(issues, "daemon/service options are incompatible with managed foreground process ownership")
	}
	if hasOption(args, "--") {
		issues = append(issues, "the -- option terminator cannot be combined with managed adapter options")
	}
	// getopt_long accepts unique prefixes; accepting these would allow --dae to
	// bypass the foreground restriction or --host to bypass guided list checks.
	protected := []string{"--daemon", "--daemonize", "--service"}
	if p.Engine == "byedpi" {
		protected = append(protected, "--ip", "--hosts", "--auto", "--transparent")
	}
	if p.Engine == "zapret" || p.Engine == "zapret2" {
		protected = append(protected, "--new", "--hostlist", "--hostlist-exclude", "--hostlist-auto", "--bind-addr", "--bind-iface", "--bind-iface4", "--bind-iface6")
	}
	for _, arg := range args {
		if nativeargs.Abbreviates(arg, protected...) {
			issues = append(issues, "spell managed option names in full; abbreviated options are not supported")
		}
	}

	switch p.Engine {
	case "byedpi":
		for _, a := range args {
			// For example -Ui0.0.0.0 and -UD are valid getopt clusters. A
			// restricted syntax keeps loopback and process ownership auditable.
			if nativeargs.ShortCluster(a) {
				issues = append(issues, "ByeDPI short options must be separate arguments; use full long options instead of clusters or attached values")
			}
		}
		// Global listen options precede groups; an explicit loopback is mandatory
		// because upstream's default is 0.0.0.0.
		for i := 0; i < len(args); i++ {
			a := args[i]
			var bind string
			bindOption := false
			if a == "-i" || a == "--ip" {
				bindOption = true
				if i+1 < len(args) {
					bind = args[i+1]
				} else {
					issues = append(issues, "missing ByeDPI listen IP")
				}
			}
			if strings.HasPrefix(a, "--ip=") {
				bindOption = true
				bind = strings.TrimPrefix(a, "--ip=")
			}
			if strings.HasPrefix(a, "-i") && !strings.HasPrefix(a, "--") && len(a) > 2 {
				bindOption = true
				bind = a[2:]
			}
			if bindOption {
				if ip := net.ParseIP(bind); ip == nil || !ip.IsLoopback() {
					issues = append(issues, "managed ByeDPI must listen on a loopback IP (127.0.0.1 or ::1)")
				}
			}
		}
		// Always inject the default before user arguments. A protected-looking
		// token may actually be consumed by an upstream --comment option.
		args = append([]string{"--ip", "127.0.0.1"}, args...)
		if hasOption(args, "--transparent", "-E") {
			issues = append(issues, "managed ByeDPI supports explicit SOCKS mode only; transparent redirection is external")
		}
		if in || out {
			if hasOption(args, "--auto", "-A", "--hosts", "-H") || hasPrefix(args, "-A") || hasPrefix(args, "-H") {
				issues = append(issues, "managed ByeDPI domain rules cannot be mixed with custom --auto/--hosts groups; clear the guided lists to manage groups manually")
			}
			prefix := []string{}
			if out {
				prefix = append(prefix, "--hosts", exclude, "--auto=none")
			}
			if in {
				prefix = append(prefix, "--hosts", include)
			}
			args = append(prefix, args...)
			if in {
				args = append(args, "--auto=none")
			}
		}
		warnings = append(warnings, "Use SOCKS5 in the target app, with proxy DNS where supported. Domain exclusions disable manipulation for those connections; traffic still uses the local proxy.")
	case "zapret", "zapret2":
		for _, a := range args {
			if len(a) > 2 && a[0] == '-' && a[1] != '-' && ((a[1] >= 'a' && a[1] <= 'z') || (a[1] >= 'A' && a[1] <= 'Z')) {
				issues = append(issues, "spell zapret long options with two dashes; single-dash long options can bypass managed rule checks")
			}
		}
		if len(args) > 0 && (strings.HasPrefix(args[0], "@") || strings.HasPrefix(args[0], "$")) {
			issues = append(issues, "zapret argument-file shortcuts are not supported: they can ignore generated rules and hide daemon options; paste the native arguments explicitly")
		}
		if (in || out) && hasPrefix(args, "--hostlist") {
			issues = append(issues, "guided domain lists cannot be mixed with native --hostlist options; use one source of rules")
		}
		filters := []string{}
		if in {
			if usesDomainFiles(p.Engine) {
				filters = append(filters, "--hostlist="+include)
			} else {
				filters = append(filters, "--hostlist-domains="+strings.ToLower(strings.Join(p.Routing.IncludeDomains, ",")))
			}
		}
		if out {
			if usesDomainFiles(p.Engine) {
				filters = append(filters, "--hostlist-exclude="+exclude)
			} else {
				filters = append(filters, "--hostlist-exclude-domains="+strings.ToLower(strings.Join(p.Routing.ExcludeDomains, ",")))
			}
		}
		if !usesDomainFiles(p.Engine) && (in || out) {
			warnings = append(warnings, "Guided domains are passed inline on Unix so upstream privilege dropping can still read them. Domain names are visible in the process argument list.")
		}
		// Every --new section is independent. Applying only to the last section
		// would silently bypass exclusions in earlier strategies.
		if len(filters) > 0 {
			expanded := []string{}
			for _, a := range args {
				if a == "--new" {
					expanded = append(expanded, filters...)
				}
				expanded = append(expanded, a)
			}
			args = append(expanded, filters...)
		}
		if p.Engine == "zapret2" {
			if !hasOption(args, "--lua-desync") {
				issues = append(issues, "zapret2 needs an explicit --lua-desync strategy; add tested native arguments")
			}
			warnings = append(warnings, "zapret2 Lua arguments execute code. Use trusted upstream Lua assets and absolute asset paths; the working directory is the executable directory.")
		}
		if base == "tpws" {
			for i, a := range args {
				if strings.HasPrefix(a, "--bind-iface") {
					issues = append(issues, "managed tpws uses a loopback address; interface binding is not supported")
				}
				if a == "--bind-addr" || strings.HasPrefix(a, "--bind-addr=") {
					var value string
					if a == "--bind-addr" {
						if i+1 < len(args) {
							value = args[i+1]
						}
					} else {
						value = strings.TrimPrefix(a, "--bind-addr=")
					}
					if ip := net.ParseIP(value); ip == nil || !ip.IsLoopback() {
						issues = append(issues, "managed tpws must bind a loopback IP")
					}
				}
			}
			args = append([]string{"--bind-addr=127.0.0.1"}, args...)
			if !hasOption(args, "--socks") {
				issues = append(issues, "managed tpws requires --socks; transparent PF/iptables setup is external")
			}
			if !hasOption(args, "--port") {
				issues = append(issues, "tpws needs an explicit --port for its SOCKS listener")
			}
			warnings = append(warnings, "tpws is a SOCKS proxy here; configure applications explicitly. Bind it to a loopback address.")
		} else {
			warnings = append(warnings, "Packet interception and privileges must already be configured: WinDivert on Windows, NFQUEUE on Linux, or divert sockets/firewall rules on BSD. AccessWeaver does not install these rules.")
		}
		if p.Engine == "zapret" {
			warnings = append(warnings, "zapret 1 is end-of-life upstream; use zapret2 for actively maintained packet strategies where supported.")
		}
	case "goodbyedpi":
		if in && hasOption(args, "--blacklist") {
			issues = append(issues, "use guided includes or native --blacklist arguments, not both")
		}
		if in {
			args = append(args, "--blacklist", include)
		}
		warnings = append(warnings, "Requires an elevated Windows process and the official compatible WinDivert DLL/driver files. A domain include list filters manipulation, not every packet-capture effect.")
	case "wiresock":
		if p.ConfigPath == "" {
			issues = append(issues, "WireSock requires configPath to an existing local WireGuard .conf file")
		}
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "-lac":
			case "-log-level", "-network-lock":
				if i+1 < len(args) {
					i++
				} else {
					issues = append(issues, "missing WireSock option value")
				}
			default:
				issues = append(issues, "managed WireSock accepts only -log-level, -lac and -network-lock; use configPath for configuration")
			}
		}
		prefix := []string{"run", "-config", p.ConfigPath}
		if !hasOption(args, "-log-level") {
			prefix = append(prefix, "-log-level", "error")
		}
		args = append(prefix, args...)
		warnings = append(warnings, "WireSock SDK has its own evaluation/commercial license and telemetry policy. App selection belongs in its .conf file; foreground mode only covers the current user's processes.", "If network lock is enabled, an abnormal termination may require the vendor reset-network-lock command to restore connectivity.")
	case "sing-box", "xray":
		if p.ConfigPath == "" {
			issues = append(issues, p.Engine+" requires configPath to an existing local configuration")
		}
		if hasOption(args, "run", "-c", "--config", "-config", "-C", "--config-directory", "-confdir") {
			issues = append(issues, "the adapter supplies run and configPath; remove duplicate commands/configuration flags")
		}
		if p.Engine == "sing-box" && (hasPrefix(args, "-c") || hasPrefix(args, "-C")) {
			issues = append(issues, "use configPath instead of attached sing-box configuration flags")
		}
		flag := "-c"
		if p.Engine == "xray" {
			flag = "-config"
		}
		args = append([]string{"run", flag, p.ConfigPath}, args...)
		warnings = append(warnings, "Review the external configuration before launch: listeners, routing, DNS and TUN options are delegated to the engine and may change network behavior.")
	case "spoofdpi":
		warnings = append(warnings, "Check the flags for your installed SpoofDPI version, particularly its system-proxy option. Proxy settings may otherwise be changed by the engine, especially on macOS.")
	}
	return args, warnings, issues
}

// Prepare verifies all prerequisites again, then materializes only generated data
// files. It never evaluates a shell command or changes a system proxy/firewall.
func Prepare(p profile.Profile, root string) (string, []string, error) {
	return prepareWithGuard(p, root, managed.NewGuard(nil))
}
func prepareWithGuard(p profile.Profile, root string, guard *managed.Guard) (string, []string, error) {
	plan, err := previewWithGuard(p, root, guard)
	if err != nil {
		return "", nil, err
	}
	if plan.policyError != nil {
		return "", nil, plan.policyError
	}
	if !plan.Ready {
		return "", nil, errors.New(strings.Join(plan.Issues, "; "))
	}
	if p.Engine == "wiresock" && len(p.Routing.Applications) > 0 {
		data, err := os.ReadFile(p.ConfigPath)
		if err != nil {
			return "", nil, err
		}
		var lines []string
		for _, line := range strings.Split(string(data), "\n") {
			key, _, has := strings.Cut(line, "=")
			if has && (strings.EqualFold(strings.TrimSpace(key), "AllowedApps") || strings.EqualFold(strings.TrimSpace(key), "DisallowedApps")) {
				continue
			}
			lines = append(lines, line)
		}
		text := strings.TrimRight(strings.Join(lines, "\n"), "\r\n") + "\nAllowedApps = " + strings.Join(p.Routing.Applications, ", ") + "\n"
		if err := profile.AtomicWrite(filepath.Join(root, "generated", p.ID+"-wiresock.conf"), []byte(text)); err != nil {
			return "", nil, err
		}
	}
	if !usesDomainFiles(p.Engine) {
		return plan.Binary, plan.Args, nil
	}
	for _, item := range []struct {
		suffix string
		values []string
	}{{"include", p.Routing.IncludeDomains}, {"exclude", p.Routing.ExcludeDomains}} {
		if len(item.values) == 0 {
			continue
		}
		file, err := filepath.Abs(filepath.Join(root, "generated", p.ID+"-"+item.suffix+".txt"))
		if err != nil {
			return "", nil, err
		}
		if err := profile.AtomicWrite(file, []byte(strings.ToLower(strings.Join(item.values, "\n"))+"\n")); err != nil {
			return "", nil, err
		}
	}
	return plan.Binary, plan.Args, nil
}

func launchPolicyInput(p profile.Profile, binary string) (managed.LaunchRequest, error) {
	digest, err := p.ExecutionDigest()
	if err != nil {
		return managed.LaunchRequest{}, err
	}
	return managed.LaunchRequest{Engine: p.Engine, InputSHA256: digest, Binary: binary, ConfigPath: p.ConfigPath,
		GeneratedInputs: len(p.Routing.IncludeDomains) > 0 || len(p.Routing.ExcludeDomains) > 0 || len(p.Routing.Applications) > 0, RawArguments: len(p.Args) > 0}, nil
}
func checkLaunchPolicy(guard *managed.Guard, p profile.Profile, binary string) error {
	input, err := launchPolicyInput(p, binary)
	if err != nil {
		return err
	}
	return guard.Launch(input)
}
func launchPolicyAuthorization(guard *managed.Guard, p profile.Profile, binary string) ([]string, *managed.Authorization, error) {
	input, err := launchPolicyInput(p, binary)
	if err != nil {
		return nil, nil, err
	}
	return guard.AuthorizeLaunch(input)
}
