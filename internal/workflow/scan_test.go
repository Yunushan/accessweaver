package workflow

import (
	"strings"
	"testing"
)

func TestScanSelectionUsesCompletedCommonReport(t *testing.T) {
	output := `debug failed trial winws2 --lua-desync=fake:blob=bad
* SUMMARY
test_https_tls12 ipv4 discord.com : /opt/nfq2/winws2 --lua-desync=multisplit:pos=2
test_https_tls12 ipv4 discord.gg : /opt/nfq2/winws2 --lua-desync=fake:blob=other
* COMMON
test_https_tls12 ipv4 : /opt/nfq2/winws2 --lua-desync=multisplit:pos=3
test_http3 ipv4 : winws2 --lua-desync=fake:blob=quic
`
	strategy, err := SelectScanStrategy(output, "zapret2")
	if err != nil {
		t.Fatal(err)
	}
	if !strategy.Common || strategy.Protocol != "https" || len(strategy.Args) != 1 || strategy.Args[0] != "--lua-desync=multisplit:pos=3" {
		t.Fatalf("wrong strategy: %+v", strategy)
	}
}
func TestScanCannotInstallFailedPartialOrOpaqueCommands(t *testing.T) {
	for _, report := range []string{
		"winws2 --lua-desync=fake:blob=x",
		"* SUMMARY\nworking without bypass",
		"* SUMMARY\ntest_https_tls12 ipv4 example.com : winws2 --lua-desync=x --daemon",
		"* SUMMARY\ntest_https_tls12 ipv4 example.com : winws2 --lua-desync=x --hostlist=temporary.txt",
		"* SUMMARY\ntest_https_tls12 ipv4 example.com : winws2 --lua-desync=x\n* COMMON\n",
	} {
		if _, err := SelectScanStrategy(report, "zapret2"); err == nil {
			t.Fatalf("unsafe/incomplete report accepted: %s", report)
		}
	}
}
func TestScanArgumentsRemainLiteral(t *testing.T) {
	report := `* SUMMARY
test_https_tls13 ipv4 example.com : winws --dpi-desync=fake "--comment=literal;$(not-evaluated)"`
	candidate, err := SelectScanStrategy(report, "zapret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(candidate.Args[1], "$(not-evaluated)") {
		t.Fatal("literal argument changed")
	}
}

func TestScanRejectsStrategiesFromAnotherEngine(t *testing.T) {
	for _, tc := range []struct {
		engine, executable, flag string
	}{
		{"zapret", "winws2", "--dpi-desync=fake"},
		{"zapret2", "winws", "--lua-desync=fake"},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			report := "* SUMMARY\ntest_https ipv4 : " + tc.executable + " " + tc.flag
			if _, err := SelectScanStrategy(report, tc.engine); err == nil {
				t.Fatal("accepted a strategy reported for the other executable")
			}
		})
	}
}

func TestScanSkipsMismatchedExecutableBeforeValidCommonStrategy(t *testing.T) {
	report := `* SUMMARY
* COMMON
test_https ipv4 : winws --lua-desync=incorrect
test_https ipv4 : "C:\tools\WINWS2.EXE" --lua-desync=correct`
	strategy, err := SelectScanStrategy(report, "zapret2")
	if err != nil || len(strategy.Args) != 1 || strategy.Args[0] != "--lua-desync=correct" || !strategy.Common {
		t.Fatalf("valid matching strategy was not selected: %+v, %v", strategy, err)
	}
}

func TestScanNeverPromotesCoverageToCommon(t *testing.T) {
	report := `* SUMMARY
 test_https ipv4 example.com : winws2 --lua-desync=individual
* COMMON
* COVERAGE
1/2 : test_https ipv4 : winws2 --lua-desync=partial`
	if _, err := SelectScanStrategy(report, "zapret2"); err == nil {
		t.Fatal("coverage-only result was promoted to the common intersection")
	}
}

func TestScanSelectsOnlyActualCommonSection(t *testing.T) {
	report := `* SUMMARY
 test_https ipv4 example.com : winws2 --lua-desync=individual
* COMMON
 test_http ipv4 : winws2 --lua-desync=common
* COVERAGE
1/2 : test_https ipv4 : winws2 --lua-desync=partial`
	strategy, err := SelectScanStrategy(report, "zapret2")
	if err != nil || strategy.Protocol != "http" || !strategy.Common || len(strategy.Args) != 1 || strategy.Args[0] != "--lua-desync=common" {
		t.Fatalf("did not retain the actual common result: %+v, %v", strategy, err)
	}
}

func TestScanRejectsMalformedSectionOrderAndMarkers(t *testing.T) {
	for _, report := range []string{
		"* COMMON\ntest_https ipv4 : winws2 --lua-desync=x",
		"* SUMMARY EXTRA\ntest_https ipv4 : winws2 --lua-desync=x",
		"* SUMMARY\ntest_https ipv4 : winws2 --lua-desync=x\n* COVERAGE",
		"* SUMMARY\ntest_https ipv4 : winws2 --lua-desync=x\n* SUMMARY",
		"* SUMMARY\ntest_https ipv4 : winws2 --lua-desync=x\n* OTHER\n* COMMON",
	} {
		if _, err := SelectScanStrategy(report, "zapret2"); err == nil {
			t.Fatal("malformed section sequence was accepted")
		}
	}
}

func TestScanDoesNotTreatCommonTextAsASection(t *testing.T) {
	report := "* SUMMARY\ntest_https ipv4 example.com : winws2 --lua-desync=ok\nNote: * COMMON is not a heading"
	strategy, err := SelectScanStrategy(report, "zapret2")
	if err != nil || strategy.Common || len(strategy.Args) != 1 || strategy.Args[0] != "--lua-desync=ok" {
		t.Fatalf("prose was treated as a common section: %+v, %v", strategy, err)
	}
}

func TestMultiTargetScanRequiresExplicitCommonSection(t *testing.T) {
	individual := "* SUMMARY\ntest_https ipv4 example.com : winws2 --lua-desync=individual"
	if _, err := SelectScanStrategyWithCommonRequirement(individual, "zapret2", true); err == nil {
		t.Fatal("multi-target scan accepted a report without a common section")
	}
	if _, err := SelectScanStrategyWithCommonRequirement(individual, "zapret2", false); err != nil {
		t.Fatalf("single-target selection was refused: %v", err)
	}
	common := individual + "\n* COMMON\ntest_https ipv4 : winws2 --lua-desync=common"
	strategy, err := SelectScanStrategyWithCommonRequirement(common, "zapret2", true)
	if err != nil || !strategy.Common || len(strategy.Args) != 1 || strategy.Args[0] != "--lua-desync=common" {
		t.Fatalf("valid common strategy was not selected: %+v, %v", strategy, err)
	}
}

func TestScanProtocolUsesTestNameNotTarget(t *testing.T) {
	for _, tc := range []struct{ test, target, want string }{
		{"curl_test_http", "https.example.com", "http"},
		{"curl_test_https_tls12", "http3.example.com", "https"},
		{"curl_test_https_tls13", "quic.example.com", "https"},
		{"curl_test_http3", "https.example.com", "quic"},
	} {
		report := "* SUMMARY\n" + tc.test + " ipv4 " + tc.target + " : winws2 --lua-desync=fixture"
		got, err := SelectScanStrategy(report, "zapret2")
		if err != nil || got.Protocol != tc.want {
			t.Fatalf("test %s classified as %s, want %s: %v", tc.test, got.Protocol, tc.want, err)
		}
	}
	if _, err := SelectScanStrategy("* SUMMARY\nunknown ipv4 https.example.com : winws2 --lua-desync=fixture", "zapret2"); err == nil {
		t.Fatal("unknown test accepted based on hostname")
	}
}

func TestScanGeneratedArgumentsRespectWorkflowLimits(t *testing.T) {
	prefix := "* SUMMARY\ncurl_test_http ipv4 example.com : winws2 "
	for _, args := range []string{
		"--lua-desync=" + strings.Repeat("x", 4096),
		"--lua-desync=x " + strings.Repeat("--x ", 125),
		"--lua-desync=x --x=\"" + strings.Repeat(" ", 32767) + "\"",
	} {
		if _, err := SelectScanStrategy(prefix+args, "zapret2"); err == nil {
			t.Fatal("scan accepted arguments outside the workflow limits")
		}
	}
	maxArg := "--lua-desync=" + strings.Repeat("x", 4096-len("--lua-desync="))
	if _, err := SelectScanStrategy(prefix+maxArg, "zapret2"); err != nil {
		t.Fatalf("maximum-length argument rejected: %v", err)
	}
	valid := "--lua-desync=x " + strings.Repeat("--x ", 124)
	strategy, err := SelectScanStrategy(prefix+valid, "zapret2")
	if err != nil || len(strategy.Args) != 125 {
		t.Fatalf("valid limit rejected: %d arguments, %v", len(strategy.Args), err)
	}
}
