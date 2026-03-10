package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for pam-pocketid.
type Config struct {
	// OIDC settings (Pocket ID)
	IssuerURL    string // OIDC issuer URL (Pocket ID base URL)
	ClientID     string // OIDC client ID
	ClientSecret string // OIDC client secret

	// Server settings
	ListenAddr  string        // Address to listen on (default ":8090")
	ExternalURL string        // Public URL of this server (for redirects)
	ChallengeTTL time.Duration // How long challenges stay valid (default 120s)
	SharedSecret string        // Shared secret for PAM helper auth

	// PAM helper settings (used by client mode)
	ServerURL   string        // URL of the auth server
	PollInterval time.Duration // How often to poll (default 2s)
	Timeout     time.Duration  // Max time to wait for approval (default 120s)
}

// LoadServerConfig loads server configuration from environment variables.
func LoadServerConfig() (*Config, error) {
	cfg := &Config{
		IssuerURL:    os.Getenv("PAM_POCKETID_ISSUER_URL"),
		ClientID:     os.Getenv("PAM_POCKETID_CLIENT_ID"),
		ClientSecret: os.Getenv("PAM_POCKETID_CLIENT_SECRET"),
		ListenAddr:   envOrDefault("PAM_POCKETID_LISTEN", ":8090"),
		ExternalURL:  os.Getenv("PAM_POCKETID_EXTERNAL_URL"),
		SharedSecret: os.Getenv("PAM_POCKETID_SHARED_SECRET"),
	}

	ttlSec := envOrDefaultInt("PAM_POCKETID_CHALLENGE_TTL", 120)
	cfg.ChallengeTTL = time.Duration(ttlSec) * time.Second

	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("PAM_POCKETID_ISSUER_URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("PAM_POCKETID_CLIENT_ID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("PAM_POCKETID_CLIENT_SECRET is required")
	}
	if cfg.ExternalURL == "" {
		return nil, fmt.Errorf("PAM_POCKETID_EXTERNAL_URL is required")
	}

	// Validate ExternalURL scheme to prevent open redirect attacks.
	// The ExternalURL is used to construct approval URLs sent to users.
	if !strings.HasPrefix(cfg.ExternalURL, "https://") && !strings.HasPrefix(cfg.ExternalURL, "http://") {
		return nil, fmt.Errorf("PAM_POCKETID_EXTERNAL_URL must start with https:// or http://")
	}

	// Enforce minimum TTL to prevent unreasonably short challenges
	if cfg.ChallengeTTL < 10*time.Second {
		return nil, fmt.Errorf("PAM_POCKETID_CHALLENGE_TTL must be at least 10 seconds")
	}
	// Enforce maximum TTL to limit exposure window
	if cfg.ChallengeTTL > 10*time.Minute {
		return nil, fmt.Errorf("PAM_POCKETID_CHALLENGE_TTL must not exceed 600 seconds")
	}

	return cfg, nil
}

// LoadClientConfig loads PAM helper configuration from environment variables.
func LoadClientConfig() (*Config, error) {
	cfg := &Config{
		ServerURL:    os.Getenv("PAM_POCKETID_SERVER_URL"),
		SharedSecret: os.Getenv("PAM_POCKETID_SHARED_SECRET"),
	}

	pollMs := envOrDefaultInt("PAM_POCKETID_POLL_MS", 2000)
	cfg.PollInterval = time.Duration(pollMs) * time.Millisecond

	timeoutSec := envOrDefaultInt("PAM_POCKETID_TIMEOUT", 120)
	cfg.Timeout = time.Duration(timeoutSec) * time.Second

	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("PAM_POCKETID_SERVER_URL is required")
	}

	// Validate ServerURL scheme to prevent SSRF via malicious config
	if !strings.HasPrefix(cfg.ServerURL, "https://") && !strings.HasPrefix(cfg.ServerURL, "http://") {
		return nil, fmt.Errorf("PAM_POCKETID_SERVER_URL must start with https:// or http://")
	}

	return cfg, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrDefaultInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
