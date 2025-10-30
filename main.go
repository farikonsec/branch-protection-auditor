package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

func main() {
	startTime = time.Now()
	fmt.Println("::group::Logs")

	logger := &Logger{}
	rateLimitHandler := &RateLimitHandler{}

	cfg, err := loadConfig()
	if err != nil {
		logger.Error(err.Error(), nil)
		os.Exit(1)
	}

	logger.Info("Starting GitHub branch protection scanner", map[string]interface{}{
		"app_id":       cfg.AppID,
		"organization": cfg.Org,
	})

	ctx := context.Background()
	client, err := newGitHubClient(ctx, cfg, rateLimitHandler, logger)
	if err != nil {
		logger.Error("Failed to initialize GitHub client", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	if err := runAudit(ctx, client, cfg.Org, logger, rateLimitHandler); err != nil {
		logger.Error("Audit run failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
}
