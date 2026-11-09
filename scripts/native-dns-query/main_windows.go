//go:build windows

// Hosted-only ordinary Windows resolver probe. Never run on a workstation.
package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
)

// Set only by the source-bound hosted build.
var sourceCommit string

// BYPASS_CACHE | WIRE_ONLY | NO_HOSTS_FILE | NO_NETBT | NO_MULTICAST |
// TREAT_AS_FQDN. No server override, UDP/TCP forcing or independent HTTP client.
const queryOptions uint32 = 0x000019c8
const maxRecords = 128
const maxAnswers = 64
const freeRecordList uint32 = 1

var sourcePattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

type queryReport struct {
	SchemaVersion                   int    `json:"schemaVersion"`
	SourceCommit                    string `json:"sourceCommit"`
	Architecture                    string `json:"architecture"`
	QueryOptions                    uint32 `json:"queryOptions"`
	Outcome                         string `json:"outcome"`
	Code                            string `json:"code"`
	FailureKind                     string `json:"failureKind"`
	AnswerCount                     int    `json:"answerCount"`
	RecordCount                     int    `json:"recordCount"`
	QueryInvoked                    bool   `json:"queryInvoked"`
	RecordsReleased                 bool   `json:"recordsReleased"`
	ProductionQualificationComplete bool   `json:"productionQualificationComplete"`
}

type queryFunc func(string, uint16, uint32, *byte, **windows.DNSRecord, *byte) error
type freeFunc func(*windows.DNSRecord, uint32)

func emptyReport(code string) queryReport {
	return queryReport{SchemaVersion: 2, Architecture: runtime.GOARCH, QueryOptions: queryOptions, Outcome: "refused", Code: code, FailureKind: "none", RecordsReleased: true}
}

// Only fixed API-status categories are published. Never inspect error text.
func queryFailureKind(err error) string {
	if err == nil {
		return "none"
	}
	var status syscall.Errno
	if !errors.As(err, &status) {
		return "other"
	}
	switch status {
	case windows.ERROR_TIMEOUT, windows.WSAETIMEDOUT:
		return "timeout"
	case windows.DNS_ERROR_RCODE_NAME_ERROR:
		return "name-error"
	case windows.DNS_ERROR_RCODE_SERVER_FAILURE:
		return "server-failure"
	case windows.DNS_ERROR_RCODE_REFUSED:
		return "refused"
	case windows.DNS_INFO_NO_RECORDS:
		return "no-records"
	case windows.ERROR_NO_NETWORK, windows.ERROR_NETWORK_UNREACHABLE, windows.ERROR_HOST_UNREACHABLE, windows.ERROR_PROTOCOL_UNREACHABLE, windows.ERROR_PORT_UNREACHABLE:
		return "no-network"
	default:
		return "other"
	}
}

func allowedName(name string) bool {
	return name == "example.com" || name == "example.net" || name == "example.org"
}

func runQuery(name string, query queryFunc, free freeFunc) (result queryReport) {
	result = emptyReport("arguments")
	if !allowedName(name) {
		return result
	}
	var records *windows.DNSRecord
	result.QueryInvoked = true
	err := query(name, windows.DNS_TYPE_A, queryOptions, nil, &records, nil)
	// Own every returned list, including partial results on an API error. Free
	// the exact native head once, before the named result can be published.
	if records != nil {
		result.RecordsReleased = false
		defer func() { free(records, freeRecordList); result.RecordsReleased = true }()
	}
	if err != nil {
		result.Code = "query-failed"
		result.FailureKind = queryFailureKind(err)
		return result
	}
	seen := make(map[*windows.DNSRecord]struct{})
	answers := 0
	for row := records; row != nil; row = row.Next {
		if _, duplicate := seen[row]; duplicate || result.RecordCount >= maxRecords {
			result.Code = "record-bound"
			return result
		}
		seen[row] = struct{}{}
		result.RecordCount++
		// Only A records in the answer section can satisfy the requested lookup.
		// Names, aliases, TTLs and addresses never enter the public report.
		if row.Type != windows.DNS_TYPE_A || row.Dw&3 != 1 {
			continue
		}
		if row.Length != 4 {
			result.Code = "record-shape"
			return result
		}
		addr := netip.AddrFrom4([4]byte{row.Data[0], row.Data[1], row.Data[2], row.Data[3]})
		if !addr.IsGlobalUnicast() {
			result.Code = "record-shape"
			return result
		}
		answers++
		if answers > maxAnswers {
			result.Code = "answer-bound"
			return result
		}
	}
	if answers == 0 {
		result.Code = "answer-bound"
		return result
	}
	result.AnswerCount = answers
	result.Code = "none"
	result.Outcome = "answered"
	return result
}

func guarded() bool {
	if runtime.Version() != "go1.27.3" || !sourcePattern.MatchString(sourceCommit) || os.Getenv("GITHUB_SHA") != sourceCommit ||
		os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("ACCESSWEAVER_EXPECT_GOOS") != "windows" ||
		os.Getenv("ACCESSWEAVER_EXPECT_GOARCH") != runtime.GOARCH {
		return false
	}
	for _, key := range []string{"ACCESSWEAVER_HISTORY_INTEROP", "ACCESSWEAVER_RECONCILIATION_INTEROP", "ACCESSWEAVER_CONTROLLER_STORAGE_INTEROP", "ACCESSWEAVER_SUPPORT_INTEROP"} {
		if _, present := os.LookupEnv(key); present {
			return false
		}
	}
	expected := uint16(0)
	switch runtime.GOARCH {
	case "amd64":
		expected = 0x8664
	case "arm64":
		expected = 0xaa64
	default:
		return false
	}
	var processMachine, nativeMachine uint16
	return windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine) == nil && processMachine == 0 && nativeMachine == expected
}

func main() {
	result := emptyReport("environment")
	if guarded() {
		result.Code = "arguments"
		if len(os.Args) == 2 && os.Args[1] == "--probe" {
			result.Outcome = "ready"
			result.Code = "none"
		} else if len(os.Args) == 3 && os.Args[1] == "--query" {
			result = runQuery(os.Args[2], windows.DnsQuery, windows.DnsRecordListFree)
		}
		result.SourceCommit = sourceCommit
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(2)
	}
}
