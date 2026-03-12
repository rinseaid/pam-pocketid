package main

import (
	"bufio"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultConfigPath is the default location for the pam-pocketid config file.
// The config file uses KEY=VALUE format (one per line, no export keyword).
// Environment variables take precedence over config file values.
const DefaultConfigPath = "/etc/pam-pocketid.conf"

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
	// Validate IssuerURL scheme (consistent with ExternalURL/ServerURL validation)
	if !strings.HasPrefix(cfg.IssuerURL, "https://") && !strings.HasPrefix(cfg.IssuerURL, "http://") {
		return nil, fmt.Errorf("PAM_POCKETID_ISSUER_URL must start with https:// or http://")
	}
	// Reject embedded credentials in IssuerURL
	if u, err := url.Parse(cfg.IssuerURL); err == nil && u.User != nil {
		return nil, fmt.Errorf("PAM_POCKETID_ISSUER_URL must not contain embedded credentials")
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
	// Reject embedded credentials — they would leak in approval URLs sent to users
	if u, err := url.Parse(cfg.ExternalURL); err == nil && u.User != nil {
		return nil, fmt.Errorf("PAM_POCKETID_EXTERNAL_URL must not contain embedded credentials")
	}

	// Enforce minimum TTL to prevent unreasonably short challenges
	if cfg.ChallengeTTL < 10*time.Second {
		return nil, fmt.Errorf("PAM_POCKETID_CHALLENGE_TTL must be at least 10 seconds")
	}
	// Enforce maximum TTL to limit exposure window
	if cfg.ChallengeTTL > 10*time.Minute {
		return nil, fmt.Errorf("PAM_POCKETID_CHALLENGE_TTL must not exceed 600 seconds")
	}

	// Require shared secret unless explicitly opted out
	if cfg.SharedSecret == "" {
		if os.Getenv("PAM_POCKETID_INSECURE") == "true" {
			log.Printf("WARNING: PAM_POCKETID_SHARED_SECRET is not set — API endpoints are unauthenticated (PAM_POCKETID_INSECURE=true)")
		} else {
			return nil, fmt.Errorf("PAM_POCKETID_SHARED_SECRET is required (set PAM_POCKETID_INSECURE=true to override)")
		}
	} else if len(cfg.SharedSecret) < 16 {
		return nil, fmt.Errorf("PAM_POCKETID_SHARED_SECRET must be at least 16 characters")
	}

	// Warn if ExternalURL uses plain HTTP (secrets and auth codes will be in cleartext)
	if strings.HasPrefix(cfg.ExternalURL, "http://") {
		log.Printf("WARNING: PAM_POCKETID_EXTERNAL_URL uses http:// — OIDC callbacks and approval URLs are not encrypted")
	}

	// Best-effort: clear secrets from environment to reduce exposure window.
	// Note: this does NOT scrub /proc/PID/environ on Linux (the initial
	// environment snapshot is immutable), but it prevents os.Getenv from
	// returning the values and removes them from child process inheritance.
	os.Unsetenv("PAM_POCKETID_SHARED_SECRET")
	os.Unsetenv("PAM_POCKETID_CLIENT_SECRET")

	return cfg, nil
}

// LoadClientConfig loads PAM helper configuration.
// Values are resolved in this order (first non-empty wins):
//  1. Environment variables
//  2. Config file (/etc/pam-pocketid.conf)
//  3. Built-in defaults
func LoadClientConfig() (*Config, error) {
	// Load config file as fallback values (env vars take precedence)
	fileVars := loadConfigFile(DefaultConfigPath)

	cfg := &Config{
		ServerURL:    configValue("PAM_POCKETID_SERVER_URL", fileVars),
		SharedSecret: configValue("PAM_POCKETID_SHARED_SECRET", fileVars),
	}

	pollMs := configValueInt("PAM_POCKETID_POLL_MS", fileVars, 2000)
	cfg.PollInterval = time.Duration(pollMs) * time.Millisecond

	timeoutSec := configValueInt("PAM_POCKETID_TIMEOUT", fileVars, 120)
	cfg.Timeout = time.Duration(timeoutSec) * time.Second

	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("PAM_POCKETID_SERVER_URL is required")
	}

	// Validate ServerURL scheme to prevent SSRF via malicious config
	if !strings.HasPrefix(cfg.ServerURL, "https://") && !strings.HasPrefix(cfg.ServerURL, "http://") {
		return nil, fmt.Errorf("PAM_POCKETID_SERVER_URL must start with https:// or http://")
	}

	// Reject URLs with embedded credentials (prevents secret leakage in logs/errors)
	if u, err := url.Parse(cfg.ServerURL); err == nil && u.User != nil {
		return nil, fmt.Errorf("PAM_POCKETID_SERVER_URL must not contain embedded credentials")
	}

	// Warn if ServerURL uses plain HTTP (shared secret will be sent in cleartext)
	if strings.HasPrefix(cfg.ServerURL, "http://") {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: PAM_POCKETID_SERVER_URL uses http:// — shared secret is transmitted in cleartext\n")
	}

	// Enforce poll interval bounds to prevent tight-loop DoS
	if cfg.PollInterval < 500*time.Millisecond {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if cfg.PollInterval > 30*time.Second {
		cfg.PollInterval = 30 * time.Second
	}

	// Enforce timeout bounds to prevent indefinite PAM session blocking
	if cfg.Timeout < 10*time.Second {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Timeout > 600*time.Second {
		cfg.Timeout = 600 * time.Second
	}

	// Enforce minimum SharedSecret length on client side (mirrors server check)
	if cfg.SharedSecret != "" && len(cfg.SharedSecret) < 16 {
		return nil, fmt.Errorf("PAM_POCKETID_SHARED_SECRET must be at least 16 characters")
	}

	return cfg, nil
}

// loadConfigFile reads KEY=VALUE pairs from a file. Lines starting with #
// are comments. Values may be optionally quoted. Returns an empty map on error.
func loadConfigFile(path string) map[string]string {
	vars := make(map[string]string)

	// Open with O_NOFOLLOW to atomically reject symlinks (no TOCTOU gap
	// between symlink check and open). All subsequent checks (permissions,
	// ownership) use the opened fd's Stat, ensuring consistency.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if !os.IsNotExist(err) {
			// O_NOFOLLOW returns ELOOP for symlinks — report it clearly
			fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: cannot open %s: %v\n", path, err)
		}
		return vars
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: cannot stat %s: %v\n", path, err)
		return vars
	}
	if !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "pam-pocketid: ERROR: %s is not a regular file — refusing to load\n", path)
		return vars
	}
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		fmt.Fprintf(os.Stderr, "pam-pocketid: ERROR: %s has group/other permissions (mode %04o) — refusing to load (fix with: chmod 600 %s)\n", path, mode, path)
		return vars
	}
	// Check file ownership — config must be owned by root to prevent
	// a non-root user from pre-creating it with a known shared secret.
	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		fmt.Fprintf(os.Stderr, "pam-pocketid: ERROR: %s is not owned by root (uid=%d) — refusing to load\n", path, uid)
		return vars
	}

	scanner := bufio.NewScanner(f)
	firstLine := true
	for scanner.Scan() {
		line := scanner.Text()
		// Strip UTF-8 BOM from first line (common when edited on Windows)
		if firstLine {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
			firstLine = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		// Strip surrounding quotes
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		vars[k] = v
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: error reading %s: %v\n", path, err)
	}
	return vars
}

// configValue returns the env var if set, otherwise the config file value.
func configValue(key string, fileVars map[string]string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fileVars[key]
}

// configValueInt returns the env var as int if set, otherwise the config file
// value as int, otherwise the default.
func configValueInt(key string, fileVars map[string]string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	if v, ok := fileVars[key]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
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
