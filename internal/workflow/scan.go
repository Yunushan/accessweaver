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
	if engine != "zapret" && engine != "zapret2" {
		return nil, errors.New("only Zapret scans produce native strategy candidates")
	}
	if len(output) > 16<<20 {
		return nil, errors.New("blockcheck report exceeds 16 MiB")
	}
	inSummary, common := false, false
	strategies := []ScanStrategy{}
	seen := map[string]bool{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "* SUMMARY") {
			inSummary = true
			common = false
			continue
		}
		if strings.HasPrefix(upper, "* COMMON") {
			inSummary = true
			common = true
			continue
		}
		if !inSummary || strings.Contains(strings.ToLower(line), "not working") {
			continue
		}
		match := reportedCommand.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		args, err := ParseArguments(match[2])
		if err != nil {
			continue
		}
		valid, hasStrategy := true, false
		for _, arg := range args {
			if arg == "--" || strings.HasPrefix(arg, "--daemon") || strings.HasPrefix(arg, "--service") || strings.HasPrefix(arg, "--hostlist") || arg == "-D" {
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
		prefix := strings.ToLower(line[:strings.Index(line, match[0])])
		protocol := ""
		switch {
		case strings.Contains(prefix, "http3") || strings.Contains(prefix, "quic"):
			protocol = "quic"
		case strings.Contains(prefix, "https") || strings.Contains(prefix, "tls"):
			protocol = "https"
		case strings.Contains(prefix, "http"):
			protocol = "http"
		default:
			continue
		}
		key := protocol + "\x00" + strings.Join(args, "\x00")
		if common {
			key += "\x00common"
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		strategies = append(strategies, ScanStrategy{Args: args, Protocol: protocol, Common: common})
	}
	if !inSummary {
		return nil, errors.New("blockcheck did not produce a completed SUMMARY")
	}
	if len(strategies) == 0 {
		return nil, errors.New("completed scan reported no usable Windows strategy")
	}
	return strategies, nil
}

// Prefer HTTPS in the common intersection. A multi-domain report with an empty
// intersection must not silently install an individual-domain success instead.
func SelectScanStrategy(output, engine string) (ScanStrategy, error) {
	strategies, err := ParseScanOutput(output, engine)
	if err != nil {
		return ScanStrategy{}, err
	}
	requireCommon := strings.Contains(strings.ToUpper(output), "* COMMON")
	for _, protocol := range []string{"https", "http", "quic"} {
		for _, candidate := range strategies {
			if candidate.Protocol == protocol && (!requireCommon || candidate.Common) {
				return candidate, nil
			}
		}
	}
	return ScanStrategy{}, errors.New("no strategy was validated in the common intersection; review individual results before installing manually")
}
