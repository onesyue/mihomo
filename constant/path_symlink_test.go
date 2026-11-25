package constant

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// YueLink SEC1: a symlink planted inside the home dir must not let a path
// that is lexically inside it resolve — or be written — outside it.

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink needs privilege on this runner: %v", err)
		}
		t.Fatal(err)
	}
}

func testHome(t *testing.T) (home, outside string) {
	t.Helper()
	base := t.TempDir()
	home = filepath.Join(base, "home")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{home, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return home, outside
}

func TestIsSafePathRejectsSymlinkEscape(t *testing.T) {
	home, outside := testHome(t)
	symlinkOrSkip(t, outside, filepath.Join(home, "ruleset"))
	p := &path{homeDir: home}

	if p.IsSafePath("ruleset/x.mrs") {
		t.Fatal("a directory symlink leading out of home was accepted")
	}
	if p.IsSafePath(filepath.Join(home, "ruleset", "new", "deeper.mrs")) {
		t.Fatal("a not-yet-existing path under an escaping link was accepted")
	}
	// Control: an ordinary path in home is still safe.
	if !p.IsSafePath("proxies/a.yaml") {
		t.Fatal("ordinary relative path rejected")
	}
}

func TestIsSafePathRejectsDanglingFinalLink(t *testing.T) {
	home, outside := testHome(t)
	// Target does not exist yet: os.WriteFile would create it outside.
	symlinkOrSkip(t, filepath.Join(outside, "created-by-root"), filepath.Join(home, "cache.db"))
	p := &path{homeDir: home}
	if p.IsSafePath("cache.db") {
		t.Fatal("a dangling link leading out of home was accepted")
	}
}

func TestIsSafePathAcceptsLinkThatStaysInside(t *testing.T) {
	home, _ := testHome(t)
	if err := os.MkdirAll(filepath.Join(home, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, filepath.Join(home, "real"), filepath.Join(home, "alias"))
	p := &path{homeDir: home}
	if !p.IsSafePath("alias/file") {
		t.Fatal("a link that stays inside home was rejected")
	}
}

func TestIsSafePathHomeItselfBehindLink(t *testing.T) {
	// macOS: /var -> /private/var. A home dir reached through a link must
	// still accept its own children.
	home, _ := testHome(t)
	link := filepath.Join(filepath.Dir(home), "home-link")
	symlinkOrSkip(t, home, link)
	p := &path{homeDir: link}
	if !p.IsSafePath("ruleset/yueto/a.mrs") {
		t.Fatal("home reached through a link rejected its own child")
	}
}

func TestWriteFileBeneathRefusesEscapes(t *testing.T) {
	home, outside := testHome(t)
	symlinkOrSkip(t, outside, filepath.Join(home, "ruleset"))
	symlinkOrSkip(t, filepath.Join(outside, "victim"), filepath.Join(home, "cache.db"))
	p := &path{homeDir: home}

	if err := p.WriteFileBeneath(filepath.Join(home, "ruleset", "x.mrs"), []byte("x"), 0o644); err == nil {
		t.Fatal("write through an escaping directory link succeeded")
	}
	if err := p.WriteFileBeneath(filepath.Join(home, "cache.db"), []byte("x"), 0o644); err == nil {
		t.Fatal("write through an escaping final link succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "x.mrs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file appeared outside home: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "victim")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("victim appeared outside home: %v", err)
	}

	// A final-component link that stays inside is refused too (O_NOFOLLOW).
	if err := os.WriteFile(filepath.Join(home, "real.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, filepath.Join(home, "real.txt"), filepath.Join(home, "inside-link"))
	if err := p.WriteFileBeneath(filepath.Join(home, "inside-link"), []byte("x"), 0o644); !errors.Is(err, ErrSymlinkTarget) {
		t.Fatalf("final-component link: got %v, want ErrSymlinkTarget", err)
	}

	// Control: a normal nested write works and creates the parents.
	target := filepath.Join(home, "rules", "deep", "a.mrs")
	if err := p.WriteFileBeneath(target, []byte("ok"), 0o644); err != nil {
		t.Fatalf("ordinary write failed: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "ok" {
		t.Fatalf("content = %q", got)
	}
}

func TestWriteFileBeneathOutsideSafePaths(t *testing.T) {
	home, outside := testHome(t)
	p := &path{homeDir: home}
	err := p.WriteFileBeneath(filepath.Join(outside, "f"), []byte("x"), 0o644)
	var notSafe ErrNotSafePath
	if !errors.As(err, &notSafe) {
		t.Fatalf("got %v, want ErrNotSafePath", err)
	}
	// Operator opt-out keeps upstream behaviour.
	p.allowUnsafePath = true
	if err := p.WriteFileBeneath(filepath.Join(outside, "f"), []byte("x"), 0o644); err != nil {
		t.Fatalf("SKIP_SAFE_PATH_CHECK write failed: %v", err)
	}
}
