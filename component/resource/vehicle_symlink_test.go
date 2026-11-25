package resource

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// YueLink SEC1: a provider write must not follow a link planted in the home
// dir — under the privileged helper that was an arbitrary root file write.
func TestFileVehicleWriteRefusesSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{home, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	prev := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(prev) })

	if err := os.Symlink(outside, filepath.Join(home, "ruleset")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink needs privilege: %v", err)
		}
		t.Fatal(err)
	}

	v := NewFileVehicle(filepath.Join(home, "ruleset", "planted.mrs"))
	if err := v.Write([]byte("payload")); err == nil {
		t.Fatal("provider write through an escaping link succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "planted.mrs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file written outside home: %v", err)
	}

	// Control: a write to an ordinary provider path in home works.
	ok := NewFileVehicle(filepath.Join(home, "rules", "a.mrs"))
	if err := ok.Write([]byte("payload")); err != nil {
		t.Fatalf("ordinary provider write failed: %v", err)
	}
}
