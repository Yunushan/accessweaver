package workflow

import (
	"bufio"
	"embed"
	"fmt"
	"strings"
)

// These native parameter collections retain their upstream MIT notice.
//
//go:embed presets/*
var presetFiles embed.FS

type Preset struct {
	Engine string   `json:"engine"`
	Name   string   `json:"name"`
	Args   []string `json:"args"`
	Source string   `json:"source"`
}

func Presets() ([]Preset, error) {
	items := []Preset{}
	for _, engine := range []string{"zapret", "zapret2", "goodbyedpi"} {
		b, err := presetFiles.ReadFile("presets/" + engine + ".txt")
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(strings.NewReader(string(b)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			name, native, ok := strings.Cut(line, ":")
			if !ok {
				return nil, fmt.Errorf("invalid %s preset", engine)
			}
			args, err := ParseArguments(native)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			items = append(items, Preset{engine, name, args, "SplitWire-Turkey 766422ed8ca9cb5360e8d9d540e80722a0508efc (MIT)"})
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	return items, nil
}

// ParseArguments splits native Windows arguments; it never evaluates a shell,
// variables, substitutions, redirections or operators.
func ParseArguments(text string) ([]string, error) {
	args := []string{}
	var word strings.Builder
	quoted, started := false, false
	for i := 0; i < len(text); {
		c := text[i]
		if (c == ' ' || c == '\t') && !quoted {
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
			i++
			continue
		}
		if c == '\\' {
			j := i
			for j < len(text) && text[j] == '\\' {
				j++
			}
			count := j - i
			if j < len(text) && text[j] == '"' {
				word.WriteString(strings.Repeat("\\", count/2))
				if count%2 == 1 {
					word.WriteByte('"')
				} else {
					quoted = !quoted
				}
				i = j + 1
				started = true
				continue
			}
			word.WriteString(strings.Repeat("\\", count))
			i = j
			started = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			started = true
			i++
			continue
		}
		if c == 0 || c == '\r' || c == '\n' {
			return nil, fmt.Errorf("native arguments contain a control character")
		}
		word.WriteByte(c)
		started = true
		i++
	}
	if quoted {
		return nil, fmt.Errorf("unclosed argument quote")
	}
	if started {
		args = append(args, word.String())
	}
	return args, nil
}
