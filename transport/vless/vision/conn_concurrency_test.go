package vision

import (
	"sync"
	"testing"
)

func TestConnectionStateIsSafeForConcurrentNetConnObservers(t *testing.T) {
	vc := &Conn{packetsToFilter: 4096}
	vc.readProcess.Store(true)
	vc.readFilterUUID.Store(true)
	vc.writeFilterApplicationData.Store(true)
	vc.writeUUIDPending.Store(true)

	clientHello := []byte{0x16, 0x03, 0x03, 0x00, 0x01, tlsHandshakeTypeClientHello}
	serverHello := make([]byte, 96)
	copy(serverHello, tlsServerHandshakeStart)
	serverHello[3], serverHello[4] = 0, 91
	serverHello[5] = tlsHandshakeTypeServerHello
	serverHello[43] = 0
	serverHello[44], serverHello[45] = 0x13, 0x01
	copy(serverHello[60:], tls13SupportedVersions)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 256 {
				vc.FilterTLS(clientHello)
				vc.FilterTLS(serverHello)
			}
		}()
		go func() {
			defer wg.Done()
			for range 256 {
				_ = vc.FrontHeadroom()
				_ = vc.RearHeadroom()
				_ = vc.NeedHandshake()
				_ = vc.Upstream()
				_ = vc.ReaderPossiblyReplaceable()
				_ = vc.ReaderReplaceable()
				_ = vc.WriterPossiblyReplaceable()
				_ = vc.WriterReplaceable()
			}
		}()
	}
	wg.Wait()
}
