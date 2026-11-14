package workflow

import (
	"errors"
	"regexp"
	"strings"
)

type ScanStrategy struct {
	Args     []string `json:"args"`
	Protocol string   `json:"protocol"`
	Common   bool     `json:"common"`
}

var reportedCommand = regexp.MustCompile(`(?i)(?:^|[\s"])(?:[^\s"]*[/\\])?(winws2?)(?:\.exe)?"?[ \t]+(--.+)$`)

// Only commands from the final report are candidates. Progress/debug lines
// contain failed trials too. Report text is never evaluated by a shell.
func ParseScanOutput(output, engine string) ([]ScanStrategy, error) {
	strategies, _, err := parseScanOutput(output, engine)
	return strategies, err
}

func parseScanOutput(output, engine string) ([]ScanStrategy, bool, error) {
	if engine != "zapret" && engine != "zapret2" {
		return nil, false, errors.New("only Zapret scans produce native strategy candidates")
	}
	if len(output) > 16<<20 {
		return nil, false, errors.New("blockcheck report exceeds 16 MiB")
	}
	section := ""
	sawSummary, sawCommon := false, false
	strategies := []ScanStrategy{}
	seen := map[string]bool{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if strings.HasPrefix(line, "*") {
			switch strings.ToUpper(line) {
			case "* SUMMARY":
				if sawSummary {
					return nil, false, errors.New("blockcheck report has duplicate SUMMARY sections")
				}
				sawSummary, section = true, "summary"
			case "* COMMON":
				if !sawSummary || sawCommon || section != "summary" {
					return nil, false, errors.New("blockcheck report has an invalid COMMON section")
				}
				sawCommon, section = true, "common"
			case "* COVERAGE":
				if !sawCommon {
					return nil, false, errors.New("blockcheck coverage has no preceding COMMON section")
				}
				section = ""
			default:
				// COVERAGE and any future section can contain partial results.
				section = ""
			}
			continue
		}
		if section == "" || strings.Contains(strings.ToLower(line), "not working") {
			continue
		}
		match := reportedCommand.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		// A reported strategy belongs to the executable that produced it.
		// Never install a winws result with winws2, or the reverse.
		expected := "winws"
		if engine == "zapret2" {
			expected = "winws2"
		}
		if !strings.EqualFold(match[1], expected) {
			continue
		}
		// Auto-install prepends three capture/filter arguments after the request
		// has been validated. Keep generated arguments within the same request
		// limits, and bound parsing before allocating an argument slice.
		if len(match[2]) > 32767 {
			continue
		}
		args, err := ParseArguments(match[2])
		if err != nil || len(args) > 125 {
			continue
		}
		valid, hasStrategy := true, false
		for _, arg := range args {
			if len(arg) > 4096 {
				valid = false
			}
			if arg == "--" || strings.HasPrefix(arg, "--daemon") || strings.HasPrefix(arg, "--service") || strings.HasPrefix(arg, "--hostlist") || arg == "-D" {
				valid = false
			}
			// Lua initializers are supplied by the installer. A reported
			// initializer can run scan-only code or refer to temporary files.
			name, _, _ := strings.Cut(arg, "=")
			if engine == "zapret2" && strings.HasPrefix(name, "--") && strings.HasPrefix("--lua-init", name) {
				valid = false
			}
			if engine == "zapret2" && strings.HasPrefix(arg, "--lua-desync=") {
				hasStrategy = true
			}
			if engine == "zapret" && strings.HasPrefix(arg, "--dpi-desync=") {
				hasStrategy = true
			}
		}
		if !valid || !hasStrategy {
			continue
		}
		// The first field is the blockcheck test function; later fields include
		// the target hostname and must not influence the reported protocol.
		fields := strings.Fields(line[:strings.Index(line, match[0])])
		if len(fields) == 0 {
			continue
		}
		protocol := ""
		switch strings.ToLower(fields[0]) {
		case "curl_test_http3", "test_http3":
			protocol = "quic"
		case "curl_test_https_tls12", "curl_test_https_tls13", "test_https", "test_https_tls12", "test_https_tls13":
			protocol = "https"
		case "curl_test_http", "test_http":
			protocol = "http"
		default:
			continue
		}
		key := protocol + "\x00" + strings.Join(args, "\x00")
		if section == "common" {
			key += "\x00common"
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		strategies = append(strategies, ScanStrategy{Args: args, Protocol: protocol, Common: section == "common"})
	}
	if !sawSummary {
		return nil, false, errors.New("blockcheck did not produce a completed SUMMARY")
	}
	if len(strategies) == 0 {
		return nil, false, errors.New("completed scan reported no usable Windows strategy")
	}
	return strategies, sawCommon, nil
}

// Prefer HTTPS in the common intersection. A multi-domain report with an empty
// intersection must not silently install an individual-domain success instead.
func SelectScanStrategy(output, engine string) (ScanStrategy, error) {
	return SelectScanStrategyWithCommonRequirement(output, engine, false)
}

// A caller that scanned multiple targets must not accept a report whose
// common intersection is absent, even if individual successes are present.
func SelectScanStrategyWithCommonRequirement(output, engine string, requireCommon bool) (ScanStrategy, error) {
	strategies, sawCommon, err := parseScanOutput(output, engine)
	if err != nil {
		return ScanStrategy{}, err
	}
	if requireCommon && !sawCommon {
		return ScanStrategy{}, errors.New("multi-target scan did not produce a COMMON section")
	}
	requireCommon = requireCommon || sawCommon
	for _, protocol := range []string{"https", "http", "quic"} {
		for _, candidate := range strategies {
			if candidate.Protocol == protocol && (!requireCommon || candidate.Common) {
				return candidate, nil
			}
		}
	}
	return ScanStrategy{}, errors.New("no strategy was validated in the common intersection; review individual results before installing manually")
}
