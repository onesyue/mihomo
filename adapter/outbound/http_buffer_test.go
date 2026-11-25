package outbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
)

func TestHTTPConnectPreservesCoalescedTargetBytes(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(fmt.Sprintf("split=%t", split), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			deadline := time.Now().Add(3 * time.Second)
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)
			const banner = "SSH-2.0-target\r\n"
			done := make(chan error, 1)
			go func() {
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					done <- err
					return
				}
				if req.Method != "CONNECT" || req.Host != "target.example:22" {
					done <- fmt.Errorf("unexpected CONNECT request: %s %s", req.Method, req.Host)
					return
				}
				response := "HTTP/1.1 200 Connection Established\r\n\r\n"
				if split {
					if _, err := io.WriteString(server, response); err != nil {
						done <- err
						return
					}
					_, err = io.WriteString(server, banner)
				} else {
					_, err = io.WriteString(server, response+banner)
				}
				if err != nil {
					done <- err
					return
				}
				responseBytes := make([]byte, len("client-data"))
				_, err = io.ReadFull(server, responseBytes)
				if err == nil && string(responseBytes) != "client-data" {
					err = fmt.Errorf("wrong client payload")
				}
				done <- err
			}()
			proxy, err := NewHttp(HttpOption{Name: "test", Server: "127.0.0.1", Port: 8080})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := proxy.StreamConnContext(context.Background(), client, &C.Metadata{Host: "target.example", DstPort: 22})
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(banner))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("target banner lost: %v", err)
			}
			if string(got) != banner {
				t.Fatalf("target banner = %q", got)
			}
			if _, err := io.Copy(conn, strings.NewReader("client-data")); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
