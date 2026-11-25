//go:build darwin

package sing_tun

import (
	"errors"
	"os"
	"testing"

	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/unix"
)

type borrowedTestTun struct {
	*os.File
	closes int
}

func (t *borrowedTestTun) Close() error { t.closes++; return t.File.Close() }

func TestBorrowedDarwinTunConfigureFailureKeepsOriginal(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	// The real Darwin constructor's utun-only socket option fails on this
	// ordinary local socket before os.File adoption. No utun or host DNS change.
	device, err := tunNewForListener(tun.Options{FileDescriptor: fds[0], MTU: 1500, EXP_RecvMsgX: true}, true)
	if err == nil || device != nil {
		t.Fatal("expected real configure failure", device, err)
	}
	if _, err := unix.Write(fds[0], []byte{42}); err != nil {
		t.Fatal("closed platform socket", err)
	}
	var got [1]byte
	if _, err := unix.Read(fds[1], got[:]); err != nil || got[0] != 42 {
		t.Fatal("original socket unusable", err)
	}
}

func TestBorrowedDarwinTunOwnsDuplicateAndCloseCannotHitReusedFD(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	var adopted *borrowedTestTun
	device, err := newBorrowedDarwinTun(tun.Options{FileDescriptor: int(reader.Fd()), MTU: 1500}, func(options tun.Options) (tun.Tun, error) {
		adopted = &borrowedTestTun{File: os.NewFile(uintptr(options.FileDescriptor), "owned-duplicate")}
		return adopted, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := int(adopted.Fd())
	if duplicate == int(reader.Fd()) {
		t.Fatal("borrowed original was transferred")
	}
	listener := &Listener{tunIf: device}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// Force the retired descriptor number to identify an unrelated live pipe.
	victim, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close()
	defer send.Close()
	if int(victim.Fd()) != duplicate {
		if err := unix.Dup2(int(victim.Fd()), duplicate); err != nil {
			t.Fatal(err)
		}
		defer unix.Close(duplicate)
	}
	if err := listener.Close(); err != nil || adopted.closes != 1 {
		t.Fatal("non-idempotent listener close", err, adopted.closes)
	}
	if _, err := send.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := unix.Read(duplicate, got[:]); err != nil || got[0] != 7 {
		t.Fatal("double-close hit unrelated reused fd", err)
	}
	if _, err := reader.Stat(); err != nil {
		t.Fatal("platform original closed", err)
	}
}

func TestBorrowedDarwinTunErrorReclaimsUnadoptedDuplicate(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	duplicate := -1
	expected := errors.New("configure failed before adoption")
	_, err = newBorrowedDarwinTun(tun.Options{FileDescriptor: int(reader.Fd()), MTU: 1500}, func(options tun.Options) (tun.Tun, error) {
		duplicate = options.FileDescriptor
		return nil, expected
	})
	if !errors.Is(err, expected) {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(duplicate), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("unadopted duplicate leaked", err)
	}
	if _, err := reader.Stat(); err != nil {
		t.Fatal("original closed", err)
	}
}
