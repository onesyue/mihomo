package reachprobe

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
)

// Error classes of the upload contract.
const (
	ErrTimeout  = "timeout"
	ErrRST      = "rst"
	ErrRefused  = "refused"
	ErrTLSAlert = "tls_alert"
	ErrPoisoned = "poisoned"
	ErrOther    = "other"
)

var errClasses = [...]string{ErrTimeout, ErrRST, ErrRefused, ErrTLSAlert, ErrPoisoned, ErrOther}

func errClassIndex(class string) int {
	for i, c := range errClasses {
		if c == class {
			return i
		}
	}
	return len(errClasses) - 1
}

// errPoisonedDNS marks a DNS answer that does not contain the signed IP.
var errPoisonedDNS = errors.New("reachprobe: dns answer does not contain the expected address")

// isCancellation reports errors that say nothing about the path: the losing
// leg of a happy-eyeballs / concurrent dial race, or a caller that gave up.
func isCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)
}

// Classify maps a handshake error to a contract error class. Several
// outbounds flatten errors to strings (fmt.Errorf with %s), so the string
// fallback is load-bearing, not decorative.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errPoisonedDNS) {
		return ErrPoisoned
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrTimeout
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return ErrRST
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ErrRefused
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "timeout"), strings.Contains(s, "timed out"), strings.Contains(s, "deadline exceeded"):
		return ErrTimeout
	case strings.Contains(s, "connection reset"), strings.Contains(s, "broken pipe"),
		strings.Contains(s, "forcibly closed"), strings.Contains(s, "unexpected eof"), s == "eof":
		return ErrRST
	case strings.Contains(s, "connection refused"), strings.Contains(s, "actively refused"):
		return ErrRefused
	case strings.Contains(s, "remote error: tls"), strings.Contains(s, "tls: alert"),
		strings.Contains(s, "crypto_error"), strings.Contains(s, "reality verification failed"):
		return ErrTLSAlert
	}
	return ErrOther
}
