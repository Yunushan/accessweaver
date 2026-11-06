//go:build linux

package linuxtrust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
)

type openingCompletionRecord struct {
	Name       string `json:"name"`
	Passed     bool   `json:"passed"`
	CheckCalls int    `json:"checkCalls"`
	CloseCalls int    `json:"closeCalls"`
}

// This opt-in test report contains only fixed source identities and case counts.
// It never serializes native errors, file names, account IDs or fixture content.
func writeOpeningCompletionEvidence(records []openingCompletionRecord) error {
	mode := os.Getenv("ACCESSWEAVER_LINUX_TRUST_EVIDENCE")
	if mode == "" {
		return nil
	}
	source := os.Getenv("GITHUB_SHA")
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Geteuid() == 0 || (mode != "normal" && mode != "race") || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) {
		return errors.New("opening evidence environment differs")
	}
	cases := openingCompletionCases()
	if len(records) != len(cases) {
		return errors.New("opening evidence cases differ")
	}
	passed := true
	for i, r := range records {
		if r.Name != cases[i].name || r.CheckCalls < 0 || r.CheckCalls > 3 || r.CloseCalls < 0 || r.CloseCalls > 3 {
			return errors.New("opening evidence case contract differs")
		}
		passed = passed && r.Passed
	}
	sources := map[string]string{}
	for _, name := range []string{"files_linux.go", "opening_completion_linux_test.go", "opening_completion_evidence_linux_test.go"} {
		digest, err := openingEvidenceHash(name, 1<<20)
		if err != nil {
			return err
		}
		sources["internal/linuxtrust/"+name] = digest
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	binaryHash, err := openingEvidenceHash(executable, 128<<20)
	if err != nil {
		return err
	}
	report := struct {
		SchemaVersion                   int                       `json:"schemaVersion"`
		SourceCommit                    string                    `json:"sourceCommit"`
		SourceSHA256                    map[string]string         `json:"sourceSHA256"`
		TestBinarySHA256                string                    `json:"testBinarySHA256"`
		Target                          string                    `json:"target"`
		GoVersion                       string                    `json:"goVersion"`
		Mode                            string                    `json:"mode"`
		Scope                           string                    `json:"scope"`
		Passed                          bool                      `json:"passed"`
		Cases                           []openingCompletionRecord `json:"cases"`
		ProductionQualificationComplete bool                      `json:"productionQualificationComplete"`
	}{1, source, sources, binaryHash, runtime.GOOS + "/" + runtime.GOARCH, runtime.Version(), mode, "owned-native-descriptor-opening-completion", passed, records, false}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > 16384 {
		return errors.New("opening evidence size differs")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		return err
	}
	folder := filepath.Join(root, "build", "linux-trust-opening")
	if err := os.MkdirAll(folder, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(folder)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("opening evidence parent differs")
	}
	resolved, err := filepath.EvalSymlinks(folder)
	if err != nil {
		return err
	}
	build, err := filepath.EvalSymlinks(filepath.Join(root, "build"))
	if err != nil {
		return err
	}
	if filepath.Dir(resolved) != build {
		return errors.New("opening evidence parent binding differs")
	}
	file, err := os.OpenFile(filepath.Join(resolved, mode+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	n, writeErr := file.Write(encoded)
	if n != len(encoded) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, file.Close())
}

func openingEvidenceHash(name string, limit int64) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return "", errors.Join(errors.New("opening evidence input differs"), err, file.Close())
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(readErr, statErr, closeErr); err != nil {
		return "", err
	}
	if n != info.Size() || n > limit || !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", errors.New("opening evidence input changed")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
