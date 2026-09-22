package xhttp

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errFakeUploadReset = errors.New("fake upload: connection reset by peer")

// fakeStreamUpTransport answers the stream-up download GET with a streaming
// body that never ends on its own, and the upload POST according to its
// fields, mimicking net/http in closing the request body on failure.
type fakeStreamUpTransport struct {
	uploadErr     error
	uploadStatus  int
	uploadBodyErr error
	downloadData  []byte
	downloadDone  chan struct{}
}

func (f *fakeStreamUpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		trace.GotConn(httptrace.GotConnInfo{Conn: c1})
	}
	if req.Method == http.MethodGet {
		pr, pw := io.Pipe()
		go func() {
			if len(f.downloadData) > 0 {
				_, _ = pw.Write(f.downloadData)
			}
			<-req.Context().Done()
			_ = pw.CloseWithError(req.Context().Err())
			if f.downloadDone != nil {
				close(f.downloadDone)
			}
		}()
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: pr}, nil
	}
	if f.uploadErr != nil {
		_ = req.Body.Close()
		return nil, f.uploadErr
	}
	go func() { _, _ = io.Copy(io.Discard, req.Body) }()
	if f.uploadBodyErr != nil {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(failingReader{f.uploadBodyErr})}, nil
	}
	pr, pw := io.Pipe()
	go func() {
		<-req.Context().Done()
		_ = pw.CloseWithError(req.Context().Err())
	}()
	if f.uploadStatus != http.StatusOK {
		_ = pw.Close()
	}
	return &http.Response{StatusCode: f.uploadStatus, Status: http.StatusText(f.uploadStatus), Body: pr}, nil
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func dialFakeStreamUp(t *testing.T, rt *fakeStreamUpTransport) net.Conn {
	t.Helper()
	client, err := NewClient(&Config{Mode: "stream-up", Path: "/xhttp", Host: "example.com"},
		func() http.RoundTripper { return rt }, nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	conn, err := client.Dial(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readWithTimeout(conn net.Conn, b []byte, timeout time.Duration) (int, error, bool) {
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := conn.Read(b)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err, true
	case <-time.After(timeout):
		return 0, nil, false
	}
}

// A failed upload request must fail the whole stream-up conn: before the fix,
// Read stayed blocked on the download stream (the server never receives the
// uplink, so it never answers) until an outer timeout fired, and Write only
// reported io.ErrClosedPipe.
func TestStreamUpUploadFailureFailsConn(t *testing.T) {
	testCases := []struct {
		name    string
		rt      *fakeStreamUpTransport
		wantErr string
	}{
		{
			name:    "RoundTripError",
			rt:      &fakeStreamUpTransport{uploadErr: errFakeUploadReset},
			wantErr: errFakeUploadReset.Error(),
		},
		{
			name:    "BadStatus",
			rt:      &fakeStreamUpTransport{uploadStatus: http.StatusForbidden},
			wantErr: "xhttp stream-up upload bad status",
		},
		{
			name:    "ResponseBodyError",
			rt:      &fakeStreamUpTransport{uploadBodyErr: errFakeUploadReset},
			wantErr: errFakeUploadReset.Error(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.rt.downloadDone = make(chan struct{})
			conn := dialFakeStreamUp(t, tc.rt)

			_, err, done := readWithTimeout(conn, make([]byte, 16), 5*time.Second)
			require.True(t, done, "Read still blocked after the upload request failed")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			if tc.rt.uploadErr != nil {
				assert.ErrorIs(t, err, tc.rt.uploadErr)
			}

			_, err = conn.Write([]byte("more uplink data"))
			require.Error(t, err)
			assert.NotErrorIs(t, err, io.ErrClosedPipe)
			assert.Contains(t, err.Error(), tc.wantErr)
			select {
			case <-tc.rt.downloadDone:
			case <-time.After(time.Second):
				t.Fatal("failed upload did not cancel its download request")
			}
		})
	}
}

// Control: a healthy upload must not disturb the download stream.
func TestStreamUpHealthyUploadKeepsConn(t *testing.T) {
	conn := dialFakeStreamUp(t, &fakeStreamUpTransport{uploadStatus: http.StatusOK, downloadData: []byte("hello")})

	_, err := conn.Write([]byte("uplink"))
	require.NoError(t, err)

	buf := make([]byte, 16)
	n, err, done := readWithTimeout(conn, buf, 5*time.Second)
	require.True(t, done)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))

	// The stream stays open: no data and no error until the conn is closed.
	_, _, done = readWithTimeout(conn, buf, 200*time.Millisecond)
	assert.False(t, done, "healthy stream-up conn was torn down")
}
