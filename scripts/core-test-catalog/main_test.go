package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
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
