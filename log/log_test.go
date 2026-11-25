package log

import (
	"sync"
	"testing"
)

func TestConcurrentLevelChangeAndLogging(t *testing.T) {
	previous := Level()
	t.Cleanup(func() { SetLevel(previous) })
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for range 10000 {
			SetLevel(DEBUG)
			SetLevel(SILENT)
		}
	})
	wg.Go(func() {
		<-start
		for range 10000 {
			got := Level()
			if got < DEBUG || got > SILENT {
				t.Errorf("invalid log level %d", got)
				return
			}
			// Exercise the same filtering read as provider callbacks, without
			// depending on console I/O scheduling for the regression.
			print(Event{LogLevel: SILENT, Payload: "level-race"})
		}
	})
	close(start)
	wg.Wait()
	for _, want := range []LogLevel{DEBUG, INFO, WARNING, ERROR, SILENT} {
		SetLevel(want)
		if got := Level(); got != want {
			t.Fatalf("level round trip: got %d, want %d", got, want)
		}
	}
}
