package main

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"
)

func TestCatalogUsesSyntaxNotStringsAndOnlyRunnableExamples(t *testing.T) {
	s := "package fixture\nimport \"testing\"\nconst fake = `func TestPrivateValue(t *testing.T){}`\nfunc TestReal(t *testing.T){}\nfunc TestMain(m *testing.M){}\nfunc Testhelper(){}\nfunc FuzzSeed(f *testing.F){}\nfunc ExamplePlain(){}\nfunc ExampleShown(){ // Output: ok\n}\n"
	f, e := parser.ParseFile(token.NewFileSet(), "", s, parser.ParseComments)
	if e != nil {
		t.Fatal(e)
	}
	got := names([]*ast.File{f})
	want := []string{"ExampleShown", "FuzzSeed", "TestReal"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog differs: %v", got)
	}
}
func TestCatalogRejectsForeignAndEscapedSources(t *testing.T) {
	root := t.TempDir()
	b, _ := json.Marshal(inputPackage{ImportPath: "foreign/private", Dir: root})
	if _, e := build(root, b); e == nil {
		t.Fatal("foreign package accepted")
	}
	b, _ = json.Marshal(inputPackage{ImportPath: module, Dir: root, TestGoFiles: []string{"../private_test.go"}})
	if _, e := build(root, b); e == nil {
		t.Fatal("escaped source accepted")
	}
}
func TestCatalogBuildsDeterministicPackagePlan(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "example_test.go")
	if e := os.WriteFile(p, []byte("package fixture\nfunc TestOne(){}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(inputPackage{ImportPath: module, Dir: root, TestGoFiles: []string{"example_test.go"}})
	got, e := build(root, b)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Packages) != 1 || !reflect.DeepEqual(got.Packages[0].Tests, []string{"TestOne"}) {
		t.Fatal("catalog differs")
	}
}

func TestCatalogRootAliasesAndPackageDirectoryEscape(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "source")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal("owned source directory unavailable")
	}
	if err := os.WriteFile(filepath.Join(target, "alias_test.go"), []byte("package fixture\nfunc TestAlias(){}\n"), 0600); err != nil {
		t.Fatal("owned source file unavailable")
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(target, alias); err != nil {
		if runtime.GOOS == "windows" && os.Getenv("GITHUB_ACTIONS") != "true" && (errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.Errno(1314))) {
			t.Skip("local Windows host does not grant symlink creation")
		}
		t.Fatal("declared alias fixture could not be created")
	}
	for _, directory := range []string{alias, target} {
		raw, err := json.Marshal(inputPackage{ImportPath: module, Dir: directory, TestGoFiles: []string{"alias_test.go"}})
		if err != nil {
			t.Fatal("owned package input encoding failed")
		}
		result, err := build(alias, raw)
		if err != nil || len(result.Packages) != 1 || !reflect.DeepEqual(result.Packages[0].Tests, []string{"TestAlias"}) {
			t.Fatal("declared root alias did not preserve its source plan")
		}
	}
	outside := t.TempDir()
	escape := filepath.Join(target, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal("owned package-directory escape fixture unavailable")
	}
	for _, files := range [][]string{nil, {"outside_test.go"}} {
		raw, err := json.Marshal(inputPackage{ImportPath: module, Dir: escape, TestGoFiles: files})
		if err != nil {
			t.Fatal("escape input encoding failed")
		}
		if _, err := build(alias, raw); err == nil {
			t.Fatal("package-directory link escape was accepted")
		}
	}
}
