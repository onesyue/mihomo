//go:build linux && with_gvisor

package sing_tun

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/dns" // initialize the production SystemResolver used by listener startup
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/tunnel"
	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/unix"
)

func TestBorrowedLinuxTunDuplicateCloseCannotHitReusedFD(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	device, err := tunNewForListener(tun.Options{FileDescriptor: int(reader.Fd()), MTU: 1500}, true)
	if err != nil {
		t.Fatal(err)
	}
	// Use the actual Linux NativeTun Read implementation through its duplicate.
	if _, err := writer.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := device.Read(got[:]); err != nil || got[0] != 42 {
		t.Fatal("native duplicate unusable", err)
	}
	l := &Listener{tunIf: device}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	victim, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close()
	defer send.Close()
	if err := l.Close(); err != nil {
		t.Fatal("repeated close", err)
	}
	if _, err := send.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	if _, err := victim.Read(got[:]); err != nil || got[0] != 7 {
		t.Fatal("reused descriptor was closed", err)
	}
	if _, err := reader.Stat(); err != nil {
		t.Fatal("platform original closed", err)
	}
}

func TestBorrowedLinuxTunNewStackFailureKeepsOriginal(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	l, err := New(LC.Tun{FileDescriptor: int(reader.Fd()), BorrowedFileDescriptor: true, MTU: 1500, Stack: C.TUNStack(99)}, tunnel.Tunnel)
	if err == nil || l != nil {
		t.Fatal("expected actual NewStack failure", l, err)
	}
	if _, err := writer.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := reader.Read(got[:]); err != nil || got[0] != 42 {
		t.Fatal("failure closed caller descriptor", err)
	}
}

func TestBorrowedLinuxRealTunRepeatedStartStop(t *testing.T) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if os.Getenv("YUELINK_REQUIRE_REAL_TUN") == "1" {
			t.Fatal(err)
		}
		t.Skip("real TUN requires /dev/net/tun and NET_ADMIN")
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	request, err := unix.NewIfreq("ylfdtest%d")
	if err != nil {
		t.Fatal(err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		if os.Getenv("YUELINK_REQUIRE_REAL_TUN") == "1" {
			t.Fatal(err)
		}
		t.Skipf("real TUN requires NET_ADMIN: %v", err)
	}
	name := request.Name()
	for range 3 {
		l, err := New(LC.Tun{Enable: true, Device: name, Stack: C.TunGvisor, MTU: 1500,
			FileDescriptor: fd, BorrowedFileDescriptor: true,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}}, tunnel.Tunnel)
		if err != nil {
			t.Fatal("actual TUN stack Start", err)
		}
		if err := l.Close(); err != nil {
			t.Fatal("actual TUN stack Stop", err)
		}
		if err := l.Close(); err != nil {
			t.Fatal("repeated actual Stop", err)
		}
		check, _ := unix.NewIfreq("")
		if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, check); err != nil || check.Name() != name {
			t.Fatal("Stop closed/replaced platform original", err)
		}
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	fd = -1
	// We have explicitly relinquished the only remaining reference.
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := net.InterfaceByName(name); err != nil {
			break
		}
		if time.Now().After(deadline) {
			entries, _ := os.ReadDir("/proc/self/fd")
			for _, entry := range entries {
				target, _ := os.Readlink("/proc/self/fd/" + entry.Name())
				info, _ := os.ReadFile("/proc/self/fdinfo/" + entry.Name())
				t.Logf("fd %s = %s %s", entry.Name(), target, info)
			}
			t.Fatal("native TUN duplicate survived Stop")
		}
		time.Sleep(time.Millisecond)
	}

}
