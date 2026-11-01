package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/profile"
)

func fixtureBinary(t *testing.T, root, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	file := filepath.Join(root, name)
	if err := os.WriteFile(file, []byte("inert adapter fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestPreviewDoesNotWriteOrExecute(t *testing.T) {
	root := t.TempDir()
	p := profile.New("preview-test", "Preview", "byedpi")
	p.Binary = fixtureBinary(t, t.TempDir(), "ciadpi")
	p.Args = []string{"--split", "2"}
	p.Routing.IncludeDomains = []string{"example.com"}
	p.Routing.ExcludeDomains = []string{"safe.example.com"}
	plan, err := Preview(p, root)
	if err != nil || !plan.Ready {
		t.Fatalf("preview: %+v %v", plan, err)
	}
	if _, err := os.Stat(filepath.Join(root, "generated")); !os.IsNotExist(err) {
		t.Fatalf("preview wrote files: %v", err)
	}
	want := []string{"--hosts", filepath.Join(root, "generated", "preview-test-exclude.txt"), "--auto=none", "--hosts", filepath.Join(root, "generated", "preview-test-include.txt"), "--ip", "127.0.0.1", "--split", "2", "--auto=none"}
	if !reflect.DeepEqual(plan.Args, want) {
		t.Fatalf("wrong group semantics:\n%v\nwant %v", plan.Args, want)
	}
	if _, _, err := Prepare(p, root); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "generated", "preview-test-exclude.txt"))
	if err != nil || string(b) != "safe.example.com\n" {
		t.Fatalf("hostlist: %q %v", b, err)
	}
}

func TestByedpiCannotEscapeManagedRules(t *testing.T) {
	p := profile.New("managed-test", "Managed", "byedpi")
	p.Binary = fixtureBinary(t, t.TempDir(), "ciadpi")
	p.Routing.IncludeDomains = []string{"example.com"}
	cases := [][]string{
		{"--ip", "0.0.0.0"}, {"-Ui0.0.0.0"}, {"-UD"}, {"--dae"},
		{"--host", ":other.com"}, {"-UH:other.com"}, {"--auto=none"},
		{"--hosts", "/tmp/custom"}, {"--transparent"}, {"--"}, {"--ip"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			p.Args = args
			plan, err := Preview(p, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if plan.Ready {
				t.Fatalf("unsafe ambiguous options accepted: %v", args)
			}
		})
	}
}

func TestZapretRulesApplyToEveryStrategy(t *testing.T) {
	p := profile.New("multi-test", "Multi", "zapret2")
	p.Args = []string{"--filter-tcp=443", "--lua-desync=multisplit:pos=2", "--new", "--filter-tcp=80", "--lua-desync=multisplit:pos=2"}
	p.Routing.IncludeDomains = []string{"example.com"}
	p.Routing.ExcludeDomains = []string{"safe.example.com"}
	args, _, issues := adapterArgs(p, "nfqws2", "include.txt", "exclude.txt")
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	want := []string{"--filter-tcp=443", "--lua-desync=multisplit:pos=2", "--hostlist=include.txt", "--hostlist-exclude=exclude.txt", "--new", "--filter-tcp=80", "--lua-desync=multisplit:pos=2", "--hostlist=include.txt", "--hostlist-exclude=exclude.txt"}
	if runtime.GOOS != "windows" {
		for i, a := range want {
			if a == "--hostlist=include.txt" {
				want[i] = "--hostlist-domains=example.com"
			}
			if a == "--hostlist-exclude=exclude.txt" {
				want[i] = "--hostlist-exclude-domains=safe.example.com"
			}
		}
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("wrong group placement: %v", args)
	}
	for _, first := range []string{"@hidden.conf", "$hidden.conf", "--host=hidden.txt", "--dae", "-daemon", "-new", "-hostlist=hidden.txt"} {
		p.Args = []string{first, "--lua-desync=multisplit:pos=2"}
		_, _, issues := adapterArgs(p, "nfqws2", "include.txt", "exclude.txt")
		if len(issues) == 0 {
			t.Errorf("opaque/abbreviated option accepted: %s", first)
		}
	}
}

func TestTPWSRequiresLocalSOCKS(t *testing.T) {
	p := profile.New("tpws-test", "TPWS", "zapret")
	p.Args = []string{"--socks", "--port=1082", "--split-pos=2"}
	args, _, issues := adapterArgs(p, "tpws", "", "")
	if len(issues) > 0 || args[0] != "--bind-addr=127.0.0.1" {
		t.Fatalf("unsafe default: %v %v", args, issues)
	}
	for _, flag := range []string{"--bind-addr=0.0.0.0", "--bind-a=0.0.0.0", "--bind-iface=eth0", "@config"} {
		p.Args = []string{flag, "--socks", "--port=1082"}
		_, _, issues := adapterArgs(p, "tpws", "", "")
		if len(issues) == 0 {
			t.Errorf("accepted %s", flag)
		}
	}
}

func TestConfigAdaptersAndWireSockHooks(t *testing.T) {
	for _, engine := range []string{"wiresock", "sing-box", "xray"} {
		p := profile.New("config-test", "Config", engine)
		p.ConfigPath = filepath.Join(t.TempDir(), "config.conf")
		args, _, issues := adapterArgs(p, "", "", "")
		if len(issues) > 0 || args[0] != "run" || args[2] != p.ConfigPath {
			t.Fatalf("%s: %v %v", engine, args, issues)
		}
		if err := os.WriteFile(p.ConfigPath, []byte("[Interface]\nPrivateKey = do-not-print\nPostUp = echo secret\n"), 0600); err != nil {
			t.Fatal(err)
		}
		err := inspectConfig(p)
		if engine == "wiresock" && (err == nil || strings.Contains(err.Error(), "do-not-print") || strings.Contains(err.Error(), "echo secret")) {
			t.Fatalf("hook validation leaked or missed: %v", err)
		}
	}
}

func TestCatalogExecutableCompatibilityAndIsolation(t *testing.T) {
	z, _ := Lookup("zapret")
	if got := z.ExecutablesFor("darwin"); !reflect.DeepEqual(got, []string{"tpws"}) {
		t.Fatal(got)
	}
	z2, _ := Lookup("zapret2")
	if z2.Supported("darwin") || len(z2.ExecutablesFor("darwin")) != 0 {
		t.Fatal("zapret2 must not claim macOS")
	}
	if got := z2.ExecutablesFor("freebsd"); !reflect.DeepEqual(got, []string{"dvtws2"}) {
		t.Fatal(got)
	}
	z.Platforms[0] = "corrupted"
	again, _ := Lookup("zapret")
	if again.Platforms[0] == "corrupted" {
		t.Fatal("mutable global catalog")
	}
}

func TestLoopbackCannotBeHiddenInsideOptionValue(t *testing.T) {
	p := profile.New("comment-test", "Comment", "byedpi")
	p.Args = []string{"--comment", "--ip=127.0.0.1"}
	args, _, issues := adapterArgs(p, "ciadpi", "", "")
	if len(issues) > 0 || len(args) < 2 || args[0] != "--ip" || args[1] != "127.0.0.1" {
		t.Fatalf("missing unconditional safe bind: %v %v", args, issues)
	}
	p.Args = []string{"--ip", "0.0.0.0", "--comment", "--ip=127.0.0.1"}
	_, _, issues = adapterArgs(p, "ciadpi", "", "")
	if len(issues) == 0 {
		t.Fatal("later option-like comment hid a public bind")
	}
}

func TestWireSockApplicationConfigurationIsPrivateCopy(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows WireSock adapter")
	}
	root := t.TempDir()
	p := profile.New("app-policy", "App policy", "wiresock")
	p.Binary = fixtureBinary(t, t.TempDir(), "wiresock-client")
	p.ConfigPath = filepath.Join(t.TempDir(), "private.conf")
	original := "[Interface]\nPrivateKey = fixture-only\n[Peer]\nAllowedApps = old.exe\nEndpoint = example.invalid:2408\n"
	if err := os.WriteFile(p.ConfigPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	p.Routing.Applications = []string{"Discord.exe", `C:\Apps\Example`}
	plan, err := Preview(p, root)
	if err != nil || !plan.Ready {
		t.Fatalf("application preview: %+v %v", plan, err)
	}
	if _, err := os.Stat(filepath.Join(root, "generated")); !os.IsNotExist(err) {
		t.Fatal("preview wrote private config")
	}
	_, args, err := Prepare(p, root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(args[2])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "AllowedApps = Discord.exe, C:\\Apps\\Example") || strings.Contains(string(data), "old.exe") {
		t.Fatal("application rules were not compiled")
	}
	data, _ = os.ReadFile(p.ConfigPath)
	if string(data) != original {
		t.Fatal("original credentials/config modified")
	}
	p.Routing.Applications = []string{"bad.exe,other.exe"}
	plan, err = Preview(p, root)
	if err != nil || plan.Ready {
		t.Fatal("ambiguous application list accepted")
	}
}

func TestWindowsInstalledComponentDiscovery(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows component locations")
	}
	data := t.TempDir()
	t.Setenv("ProgramData", data)
	t.Setenv("ProgramFiles", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	dir := filepath.Join(data, "AccessWeaver", "components", "byedpi")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	bin := fixtureBinary(t, dir, "ciadpi")
	p := profile.New("discovered", "Discovered", "byedpi")
	plan, err := Preview(p, t.TempDir())
	if err != nil || !plan.Ready || plan.Binary != bin {
		t.Fatalf("component not discovered: %+v %v", plan, err)
	}
}
