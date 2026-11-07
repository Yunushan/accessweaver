package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const module = "github.com/Yunushan/accessweaver"

type inputPackage struct {
	ImportPath   string
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
}
type packagePlan struct {
	Path  string   `json:"path"`
	Tests []string `json:"tests"`
}
type catalog struct {
	SchemaVersion int           `json:"schemaVersion"`
	Module        string        `json:"module"`
	Packages      []packagePlan `json:"packages"`
}

func testName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(r)
}
func names(files []*ast.File) []string {
	found := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			name := fn.Name.Name
			if name != "TestMain" && (testName(name, "Test") || testName(name, "Fuzz")) {
				found[name] = true
			}
		}
	}
	for _, e := range doc.Examples(files...) {
		if e.Output != "" || e.EmptyOutput {
			found["Example"+e.Name] = true
		}
	}
	out := make([]string, 0, len(found))
	for n := range found {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
func inside(root, file string) bool {
	r, e := filepath.Rel(root, file)
	return e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r)
}
func source(root, file string) ([]byte, error) {
	real, e := filepath.EvalSymlinks(file)
	if e != nil || !inside(root, real) {
		return nil, errors.New("test source outside root")
	}
	f, e := os.Open(real)
	if e != nil {
		return nil, e
	}
	before, e := f.Stat()
	if e != nil {
		return nil, errors.Join(e, f.Close())
	}
	if !before.Mode().IsRegular() || before.Size() > 2<<20 {
		return nil, errors.Join(errors.New("test source budget"), f.Close())
	}
	b, e := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	after, se := f.Stat()
	ce := f.Close()
	if e != nil || se != nil || ce != nil {
		return nil, errors.Join(e, se, ce)
	}
	if int64(len(b)) != before.Size() || len(b) > 2<<20 || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("test source changed")
	}
	return b, nil
}
func build(root string, raw []byte) (catalog, error) {
	result := catalog{SchemaVersion: 1, Module: module, Packages: []packagePlan{}}
	if len(raw) > 8<<20 {
		return result, errors.New("package input budget")
	}
	requestedRoot, e := filepath.Abs(root)
	if e != nil {
		return result, e
	}
	real, e := filepath.EvalSymlinks(requestedRoot)
	if e != nil {
		return result, e
	}
	root, e = filepath.Abs(real)
	if e != nil {
		return result, e
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	seen := map[string]bool{}
	total := 0
	for {
		var p inputPackage
		if e = decoder.Decode(&p); e == io.EOF {
			break
		} else if e != nil {
			return result, e
		}
		if p.ImportPath != module && !strings.HasPrefix(p.ImportPath, module+"/") {
			return result, errors.New("unexpected package")
		}
		// Compare actual directory spellings on both sides. Windows short names
		// and directory links may spell the same source root differently. No test
		// file is opened before canonical package containment is confirmed, even
		// for a package with no test files.
		if seen[p.ImportPath] || len(result.Packages) >= 128 || !filepath.IsAbs(p.Dir) {
			return result, errors.New("package plan differs")
		}
		directory, directoryErr := filepath.EvalSymlinks(p.Dir)
		if directoryErr != nil || !inside(root, directory) {
			return result, errors.New("package directory differs")
		}
		p.Dir = directory
		seen[p.ImportPath] = true
		fileNames := append(append([]string{}, p.TestGoFiles...), p.XTestGoFiles...)
		if len(fileNames) > 512 {
			return result, errors.New("test file budget")
		}
		files := []*ast.File{}
		for _, name := range fileNames {
			if filepath.Base(name) != name || !strings.HasSuffix(name, "_test.go") {
				return result, errors.New("test source name differs")
			}
			b, e := source(root, filepath.Join(p.Dir, name))
			if e != nil {
				return result, e
			}
			f, e := parser.ParseFile(token.NewFileSet(), "", b, parser.ParseComments|parser.SkipObjectResolution)
			if e != nil {
				return result, e
			}
			files = append(files, f)
		}
		tests := names(files)
		total += len(tests)
		if total > 20000 {
			return result, errors.New("test catalog budget")
		}
		result.Packages = append(result.Packages, packagePlan{Path: p.ImportPath, Tests: tests})
	}
	if len(result.Packages) == 0 {
		return result, errors.New("empty package plan")
	}
	sort.Slice(result.Packages, func(i, j int) bool { return result.Packages[i].Path < result.Packages[j].Path })
	return result, nil
}
func main() {
	root := flag.String("root", "", "source root")
	flag.Parse()
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, (8<<20)+1))
	if e == nil && *root != "" {
		var c catalog
		c, e = build(*root, raw)
		if e == nil {
			e = json.NewEncoder(os.Stdout).Encode(c)
		}
	}
	if e != nil || *root == "" {
		os.Stderr.WriteString("Core source catalog failed\n")
		os.Exit(1)
	}
}
