package main

import (
	"context"
	"fmt"

	"github.com/google/go-github/v53/github"
	"golang.org/x/oauth2"
)

func newGitHubClient(ctx context.Context, cfg *AppConfig, rateLimitHandler *RateLimitHandler, logger *Logger) (*github.Client, error) {
	key, err := parsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	jwtToken, err := generateJWT(cfg.AppID, key)
	if err != nil {
		return nil, fmt.Errorf("generate JWT: %w", err)
	}

	jwtClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwtToken}))
	client := github.NewClient(jwtClient)

	token, resp, err := client.Apps.CreateInstallationToken(ctx, parseInt64(cfg.InstallationID), nil)
	rateLimitHandler.HandleRateLimit(resp, logger)
	if err != nil {
		return nil, fmt.Errorf("create installation token: %w", err)
	}

	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token.GetToken()}))
	return github.NewClient(tc), nil
}
