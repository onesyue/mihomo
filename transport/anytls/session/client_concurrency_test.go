package session

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestIdleCleanupConcurrentPoolChanges(t *testing.T) {
	client := NewClient(context.Background(), nil, nil, "", time.Hour, time.Hour, 0, false)
	t.Cleanup(func() { _ = client.Close() })

	// No session is expired, so this drives only the production pool's
	// bookkeeping. Returns hold the same lock as CreateStream's close hook;
	// getIdleSession and cleanup run their actual concurrent consumer paths.
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		<-start
		for i := uint64(0); i < 5000; i++ {
			client.idleSessionLock.Lock()
			client.idleSession.Insert(i%16, &Session{idleSince: time.Now()})
			client.idleSession.Remove((i + 8) % 16)
			client.idleSessionLock.Unlock()
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 5000; i++ {
			client.getIdleSession()
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 5000; i++ {
			client.idleCleanupExpTime(time.Time{})
		}
	}()
	close(start)
	workers.Wait()
}
