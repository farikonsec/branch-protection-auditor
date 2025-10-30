package main

import (
	"fmt"
	"os"
)

// AppConfig contains the environment-derived configuration required to talk to GitHub.
type AppConfig struct {
	AppID          string
	InstallationID string
	PrivateKey     string
	Org            string
}

func loadConfig() (*AppConfig, error) {
	cfg := &AppConfig{
		AppID:          os.Getenv("APP_ID"),
		InstallationID: os.Getenv("INSTALLATION_ID"),
		PrivateKey:     os.Getenv("PRIVATE_KEY"),
		Org:            os.Getenv("GITHUB_ORG"),
	}
	if cfg.Org == "" {
		cfg.Org = "nanasec"
	}
	if cfg.AppID == "" || cfg.InstallationID == "" || cfg.PrivateKey == "" {
		return nil, fmt.Errorf("missing APP_ID, INSTALLATION_ID, or PRIVATE_KEY environment variables")
	}
	return cfg, nil
}
