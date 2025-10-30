package main

import (
	"sync"
	"time"

	"github.com/google/go-github/v53/github"
)

// RateLimitHandler centralizes GitHub rate limit handling.
type RateLimitHandler struct {
	mu sync.Mutex
}

func (r *RateLimitHandler) HandleRateLimit(resp *github.Response, logger *Logger) {
	if resp == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	remaining := resp.Rate.Remaining
	reset := resp.Rate.Reset.Time
	if remaining == 0 {
		waitDuration := time.Until(reset)
		logger.Info("Rate limit reached, sleeping until reset", map[string]interface{}{
			"reset_time": reset.Format(time.RFC3339),
			"wait_time":  waitDuration.String(),
		})
		time.Sleep(waitDuration)
	}
}
