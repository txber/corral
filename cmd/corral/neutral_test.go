package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
			if strings.Contains(strings.ToLower(text), "nono") {
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
