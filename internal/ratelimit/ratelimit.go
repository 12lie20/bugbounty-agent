package ratelimit

import (
	"sync"
	"time"
)

// AdaptiveLimiter adjusts request rate based on target feedback.
type AdaptiveLimiter struct {
	mu            sync.RWMutex
	baseDelay     time.Duration
	currentDelay  time.Duration
	maxDelay      time.Duration
	minDelay      time.Duration
	backoffFactor float64
	recoverFactor float64
}

// NewAdaptiveLimiter creates a limiter.
func NewAdaptiveLimiter(baseRPS int) *AdaptiveLimiter {
	baseDelay := time.Second / time.Duration(baseRPS)
	if baseDelay <= 0 {
		baseDelay = time.Second
	}
	return &AdaptiveLimiter{
		baseDelay:     baseDelay,
		currentDelay:  baseDelay,
		minDelay:      baseDelay / 2,
		maxDelay:      30 * time.Second,
		backoffFactor: 2.0,
		recoverFactor: 0.8,
	}
}

// Wait blocks for the current adaptive delay.
func (r *AdaptiveLimiter) Wait() {
	r.mu.RLock()
	d := r.currentDelay
	r.mu.RUnlock()
	time.Sleep(d)
}

// RecordSuccess tells the limiter it can be more aggressive.
func (r *AdaptiveLimiter) RecordSuccess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.currentDelay = time.Duration(float64(r.currentDelay) * r.recoverFactor)
	if r.currentDelay < r.minDelay {
		r.currentDelay = r.minDelay
	}
}

// RecordBlock tells the limiter to slow down.
func (r *AdaptiveLimiter) RecordBlock() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.currentDelay = time.Duration(float64(r.currentDelay) * r.backoffFactor)
	if r.currentDelay > r.maxDelay {
		r.currentDelay = r.maxDelay
	}
}

// CurrentDelay returns the current delay.
func (r *AdaptiveLimiter) CurrentDelay() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentDelay
}
