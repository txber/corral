package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// toolName matches the sandbox tool's name as a whole word, so that words
// such as "nonoverlapping" do not count.
var toolName = regexp.MustCompile(`(?i)\bnono\b`)

// namesTool reports whether text names the sandbox tool.
func namesTool(text string) bool { return toolName.MatchString(text) }

// TestCoreNamesNoTool keeps the core of corral independent of the tools it
// drives: only integration/nono and integration/pi may name them, and only
// this command links them in.
func TestCoreNamesNoTool(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found two levels up: %v", err)
	}
	forbiddenImports := []string{
		`"github.com/txber/corral/integration/nono"`,
		`"github.com/txber/corral/integration/pi"`,
	}
	toolPackages := map[string]bool{
		filepath.Join(root, "integration", "nono"): true,
		filepath.Join(root, "integration", "pi"):   true,
	}
	checked := 0
	for _, dir := range []string{"internal", "integration"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if toolPackages[path] {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			checked++
			text := string(data)
			if namesTool(text) {
				t.Errorf("%s names nono", path)
			}
			for _, imp := range forbiddenImports {
				if strings.Contains(text, imp) {
					t.Errorf("%s imports %s", path, imp)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked == 0 {
		t.Fatal("no Go files checked")
	}
}

func TestToolNameIsMatchedAsAWord(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{"nono", true},
		{"uses Nono here", true},
		{`import "github.com/txber/corral/integration/nono"`, true},
		{"nonoverlapping ranges", false},
		{"a nonobvious case", false},
	}
	for _, tt := range tests {
		if got := namesTool(tt.text); got != tt.want {
			t.Errorf("namesTool(%q) = %v, want %v", tt.text, got, tt.want)
		}
	}
}
