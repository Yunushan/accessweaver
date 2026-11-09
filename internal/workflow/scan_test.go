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
