// Offline validation of generated CycloneDX documents against pinned schemas.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("unapproved schema reference: %s", url)
}

var schemas = map[string]string{
	"bom-1.6.schema.json":  "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d",
	"spdx.schema.json":     "4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359",
	"jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}

func validateDocument(schema *jsonschema.Schema, doc any) error {
	object, ok := doc.(map[string]any)
	if !ok || object["bomFormat"] != "CycloneDX" || object["specVersion"] != "1.6" {
		return fmt.Errorf("expected CycloneDX 1.6 profile")
	}
	return schema.Validate(doc)
}

func document(path string) (any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil, fmt.Errorf("expected bounded regular JSON file")
	}
	return jsonschema.UnmarshalJSON(io.LimitReader(f, 16<<20))
}
func compileSchema(schemaDir string) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(denyLoader{})
	compiler.AssertFormat()
	for name, digest := range schemas {
		path := filepath.Join(schemaDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			return nil, fmt.Errorf("pinned schema changed: %s", name)
		}
		doc, err := document(path)
		if err != nil {
			return nil, err
		}
		if err := compiler.AddResource("http://cyclonedx.org/schema/"+name, doc); err != nil {
			return nil, err
		}
	}
	return compiler.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
}

func run() error {
	schemaDir := flag.String("schemas", "../sbom/schema", "pinned schema directory")
	flag.Parse()
	if flag.NArg() == 0 {
		return fmt.Errorf("provide one or more CycloneDX SBOM files")
	}
	schema, err := compileSchema(*schemaDir)
	if err != nil {
		return err
	}
	for _, path := range flag.Args() {
		doc, err := document(path)
		if err != nil {
			return err
		}
		if err := validateDocument(schema, doc); err != nil {
			return fmt.Errorf("invalid SBOM %s: %w", filepath.Base(path), err)
		}
		fmt.Println("CycloneDX 1.6 schema validated:", filepath.Base(path))
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
