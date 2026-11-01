package workflow

import (
	"reflect"
	"testing"
)

func TestNativeArgumentParser(t *testing.T) {
	args, err := ParseArguments(`--file="C:\some path\list.txt" "" literal;$(untouched) --lua-desync=multisplit:pos=2`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`--file=C:\some path\list.txt`, "", `literal;$(untouched)`, `--lua-desync=multisplit:pos=2`}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("got %#v", args)
	}
	if _, err := ParseArguments(`"unclosed`); err == nil {
		t.Fatal("unclosed quote accepted")
	}
}
func TestPresetCollectionsContainAllISPVariants(t *testing.T) {
	items, err := Presets()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	counts := map[string]int{}
	for _, p := range items {
		counts[p.Engine]++
		if len(p.Args) == 0 {
			t.Fatal("empty preset")
		}
		if p.Engine == "zapret2" {
			names[p.Name] = true
		}
	}
	for _, name := range []string{"Turk Telekom", "Superonline", "Vodafone", "Turksat Kablonet", "Telekom Mobil", "Turkcell Mobil", "Vodafone Mobil"} {
		if !names[name] {
			t.Fatalf("missing ISP preset %s", name)
		}
	}
	for _, engine := range []string{"zapret", "zapret2", "goodbyedpi"} {
		if counts[engine] < 5 {
			t.Fatalf("incomplete %s collection", engine)
		}
	}
}
