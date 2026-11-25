// The standalone helper keeps the server-only dependency out of the core module.
// All sockets and the cover target are loopback; stdin EOF or a hard lifetime
// terminates the process, including any server-owned background goroutines.
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	reality "github.com/xtls/reality"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	go func() { time.Sleep(4 * time.Minute); os.Exit(2) }()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture.invalid"}, DNSNames: []string{"fixture.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	must(err)
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	must(err)
	cover, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	must(err)
	go func() {
		for {
			c, e := cover.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = c.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	// Match Xray GetREALITYConfig: this protocol disables server session tickets.
	cfg := &reality.Config{SessionTicketsDisabled: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, Type: "tcp", Dest: cover.Addr().String(), ServerNames: map[string]bool{"fixture.invalid": true}, PrivateKey: private.Bytes(), ShortIds: map[[8]byte]bool{{1, 2, 3, 4, 5, 6, 7, 8}: true}, MaxTimeDiff: time.Minute}
	// The maintained server starts bounded loopback discovery for each ALPN mode.
	reality.DetectPostHandshakeRecordsLens(cfg)
	// Discovery is asynchronous. Do not admit the first client while its map
	// entries are still booleans: Server otherwise polls them at five seconds.
	readyDeadline := time.Now().Add(5 * time.Second)
	for {
		ready := true
		for alpn := range 3 {
			value, ok := reality.GlobalPostHandshakeRecordsLens.Load(fmt.Sprintf("%s fixture.invalid %d", cfg.Dest, alpn))
			_, complete := value.([]int)
			ready = ready && ok && complete
		}
		if ready {
			break
		}
		if time.Now().After(readyDeadline) {
			panic("cover discovery did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	go func() {
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				c, e := reality.Server(ctx, raw, cfg)
				if e == nil {
					serveVLESS(c)
				} else {
					fmt.Fprintln(os.Stderr, "Reality handshake:", e)
				}
			}()
		}
	}()
	must(json.NewEncoder(os.Stdout).Encode(map[string]string{"address": listener.Addr().String(), "public_key": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "short_id": "0102030405060708"}))
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = listener.Close()
	_ = cover.Close()
}
func serveVLESS(c net.Conn) {
	var header [18]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 0 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(header[17])); err != nil {
		return
	}
	var target [4]byte
	if _, err := io.ReadFull(c, target[:]); err != nil || target[0] != 1 {
		return
	}
	count := 0
	switch target[3] {
	case 1:
		count = 4
	case 2:
		var size [1]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return
		}
		count = int(size[0])
	case 3:
		count = 16
	default:
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(count)); err != nil {
		return
	}
	if _, err := c.Write([]byte{0, 0}); err != nil {
		return
	}
	reader := bufio.NewReader(c)
	prefix, err := reader.Peek(4)
	if err != nil {
		return
	}
	if string(prefix) == "GET " || string(prefix) == "HEAD" {
		for {
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			_ = req.Body.Close()
			time.Sleep(3 * time.Millisecond)
			if _, err = c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")); err != nil {
				return
			}
		}
	}
	_, _ = io.Copy(c, reader)
}
