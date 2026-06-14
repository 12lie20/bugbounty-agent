package ratelimit

import (
	"testing"
	"time"
)

func TestAdaptiveLimiter(t *testing.T) {
	l := NewAdaptiveLimiter(2) // base delay 500ms
	initial := l.CurrentDelay()
	if initial <= 0 {
		t.Fatal("initial delay should be positive")
	}

	l.RecordSuccess()
	if l.CurrentDelay() >= initial {
		t.Error("delay should decrease after success")
	}

	l.RecordBlock()
	if l.CurrentDelay() <= initial {
		t.Error("delay should increase after block")
	}

	start := time.Now()
	l.Wait()
	if time.Since(start) < l.CurrentDelay()/2 {
		t.Error("Wait did not block long enough")
	}
}
