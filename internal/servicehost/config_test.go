package servicehost

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/jsoninput"
)

func TestServiceConfigStrictAndBounded(t *testing.T) {
	valid := `{"name":"AccessWeaver-zapret2","binary":"binary.exe","args":["--example=x"],"directory":"components","logPath":"logs/out.log"}`
	cfg, err := readConfig(strings.NewReader(valid))
	if err != nil || cfg.Name != "AccessWeaver-zapret2" || len(cfg.Args) != 1 || cfg.Args[0] != "--example=x" {
		t.Fatalf("valid service config rejected: %v", err)
	}
	for _, input := range []string{
		strings.Replace(valid, `"name":`, `"name":"first","name":`, 1),
		strings.Replace(valid, `"name":`, `"Name":`, 1),
		strings.Replace(valid, `"binary":`, `"unknown":true,"binary":`, 1),
		valid + `{}`,
		strings.Replace(valid, `"binary":"binary.exe"`, `"binary":""`, 1),
		strings.Replace(valid, `"--example=x"`, `"--example=\\u0000"`, 1),
		strings.Replace(valid, `"--example=x"`, `"`+strings.Repeat("x", 4097)+`"`, 1),
		strings.Replace(valid, `["--example=x"]`, `[`+strings.Repeat(`"x",`, 128)+`"x"]`, 1),
		valid + strings.Repeat(" ", jsoninput.MaxBytes),
	} {
		if got, err := readConfig(strings.NewReader(input)); err == nil || got.Name != "" {
			t.Fatal("invalid service configuration accepted or partially returned")
		}
	}
	if _, err := readConfig(errReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("input read failure was not retained: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
