package netns

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestParseEnvReadsKeyValueLines(t *testing.T) {
	got, err := parseEnv([]byte("PATH=/usr/bin:/bin\nGREETING=hello = world\nEMPTY=\n_x1=y"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PATH=/usr/bin:/bin", "GREETING=hello = world", "EMPTY=", "_x1=y"}
	if !slices.Equal(got, want) {
		t.Errorf("parseEnv = %q, want %q", got, want)
	}
}

func TestParseEnvAcceptsAnEmptyFile(t *testing.T) {
	got, err := parseEnv(nil)
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("parseEnv(nil) = %q, %v; want an empty, non-nil list", got, err)
	}
}

func TestParseEnvRefuses(t *testing.T) {
	tests := map[string]string{
		"a line without =":         "PATH\n",
		"an empty key":             "=x\n",
		"a key with a digit first": "1A=x\n",
		"a key with a dash":        "A-B=x\n",
		"a key with a space":       "A B=x\n",
		"a blank line":             "A=x\n\nB=y\n",
		"a NUL byte":               "A=x\x00y\n",
		"a key set twice":          "A=x\nA=y\n",
		"65 lines":                 envLines(65),
	}
	for name, text := range tests {
		if got, err := parseEnv([]byte(text)); err == nil {
			t.Errorf("%s: parseEnv(%q) = %q, want an error", name, text, got)
		}
	}
}

func TestParseEnvErrorsDoNotShowValues(t *testing.T) {
	_, err := parseEnv([]byte("TOKEN=secret-one\nTOKEN=secret-two\n"))
	if err == nil {
		t.Fatal("parseEnv accepted a key set twice")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("error %q shows a value", err)
	}
}

// envLines returns an env file of n lines, each with its own key.
func envLines(n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString("K" + strconv.Itoa(i) + "=v\n")
	}
	return b.String()
}

// writeEnv writes an env file with the given mode and returns its path.
func writeEnv(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadEnvFileReadsAFileOfTheUser(t *testing.T) {
	path := writeEnv(t, "A=1\nB=2\n", 0o600)
	got, err := readEnvFile(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A=1", "B=2"}; !slices.Equal(got, want) {
		t.Errorf("readEnvFile = %q, want %q", got, want)
	}
}

func TestReadEnvFileRefusesAnotherOwner(t *testing.T) {
	path := writeEnv(t, "A=1\n", 0o600)
	if _, err := readEnvFile(path, os.Getuid()+1); err == nil {
		t.Error("readEnvFile accepted a file of another user")
	}
}

func TestReadEnvFileRefusesAGroupReadableFile(t *testing.T) {
	path := writeEnv(t, "A=1\n", 0o640)
	if _, err := readEnvFile(path, os.Getuid()); err == nil {
		t.Error("readEnvFile accepted mode 640")
	}
}

func TestReadEnvFileRefusesAnOwnerOnlyReadableFile(t *testing.T) {
	path := writeEnv(t, "A=1\n", 0o400)
	if _, err := readEnvFile(path, os.Getuid()); err == nil {
		t.Error("readEnvFile accepted mode 400")
	}
}

func TestReadEnvFileRefusesASymlink(t *testing.T) {
	path := writeEnv(t, "A=1\n", 0o600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnvFile(link, os.Getuid()); err == nil {
		t.Error("readEnvFile followed a symbolic link")
	}
}

func TestReadEnvFileRefusesAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnvFile(path, os.Getuid()); err == nil {
		t.Error("readEnvFile accepted a FIFO")
	}
}

func TestReadEnvFileRefusesADirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnvFile(dir, os.Getuid()); err == nil {
		t.Error("readEnvFile accepted a directory")
	}
}

func TestReadEnvFileRefusesALargeFile(t *testing.T) {
	path := writeEnv(t, "A="+strings.Repeat("x", maxEnvSize)+"\n", 0o600)
	if _, err := readEnvFile(path, os.Getuid()); err == nil {
		t.Error("readEnvFile accepted a file larger than 64 KiB")
	}
}
