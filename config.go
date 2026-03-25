package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// clientConfigAllowNoServer allows LoadClientConfig to succeed without SERVER_URL.
// Set to true by rotate-breakglass subcommand for local-only rotation.
var clientConfigAllowNoServer bool

// WebhookConfig describes a single webhook destination with its payload format
// and optional per-request headers.
type WebhookConfig struct {
	URL      string            `json:"url"`
	Format   string            `json:"format"` // "raw", "apprise", "discord", "slack", "ntfy", "custom"
	Headers  map[string]string `json:"headers,omitempty"`
	Template string            `json:"template,omitempty"` // for "custom" format
}

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
	ListenAddr   string        // Address to listen on (default ":8090")
	ExternalURL  string        // Public URL of this server (for redirects)
	ChallengeTTL time.Duration // How long challenges stay valid (default 120s)
	SharedSecret string        // Shared secret for PAM helper auth
	GracePeriod  time.Duration // Skip re-auth if user approved within this window (default 0 = disabled)
	OneTapMaxAge time.Duration // max time since last OIDC auth for one-tap to work without re-auth (default 24h)

	// PAM helper settings (used by client mode)
	ServerURL   string        // URL of the auth server
	PollInterval time.Duration // How often to poll (default 2s)
	Timeout     time.Duration  // Max time to wait for approval (default 120s)

	// Break-glass settings (client mode)
	BreakglassEnabled      bool   // Whether break-glass fallback is enabled (default true)
	BreakglassFile         string // Path to local bcrypt hash file (default /etc/pam-pocketid-breakglass)
	BreakglassRotationDays int    // Rotation interval in days (default 90)
	BreakglassPasswordType string // Password type: random, passphrase, alphanumeric (default random)

	// Notification settings (server mode)
	NotifyCommand        string            // Shell command to run when a new challenge is created
	NotifyEnvPassthrough []string          // Additional env var prefixes to pass to notify command (e.g., APPRISE_,TELEGRAM_)
	NotifyUsersFile      string            // Path to JSON file mapping usernames to per-user notification URLs
	NotifyUsers          map[string]string // Inline per-user notification URLs (overrides NotifyUsersFile when set)
	NotifyWebhookURL     string            // URL for webhook notifications (POST JSON) — legacy, superseded by Webhooks
	Webhooks             []WebhookConfig   // Multi-webhook destinations (parsed from PAM_POCKETID_WEBHOOKS / PAM_POCKETID_WEBHOOKS_FILE)

	// Break-glass settings (server mode)
	EscrowCommand          string    // Shell command to escrow break-glass passwords
	EscrowEnvPassthrough   []string  // Additional env var prefixes to pass to escrow command (e.g., AWS_,VAULT_)
	EscrowBackend          string    // Native escrow backend: "1password-connect", "vault", "bitwarden", "infisical"
	EscrowURL              string    // Backend base URL
	EscrowAuthID           string    // Backend auth identifier (role_id, client_id, etc.)
	EscrowAuthSecret       string    // Backend auth secret (token, secret_id, etc.)
	EscrowPath             string    // Storage location (vault name/UUID, KV path prefix, org/project, etc.)
	BreakglassRotateBefore time.Time // Tell clients to rotate if their hash file is older than this

	// History page settings (server mode)
	DefaultHistoryPageSize int // Default number of entries per page (default 10)

	// Escrow link settings (server mode)
	EscrowLinkTemplate string // URL template for viewing escrowed credentials, with {hostname} placeholder
	EscrowLinkLabel    string // Label for escrow link button (default "View password")

	// Host registry (server mode)
	HostRegistryFile string // Path to JSON file for registered hosts with per-host secrets

	// Admin access (server mode)
	AdminGroups        []string // OIDC groups that grant admin access to the dashboard
	AdminApprovalHosts []string // Hostnames requiring admin approval (glob patterns supported)

	// API access (server mode)
	APIKeys []string // Bearer tokens for programmatic API access

	// Pocket ID API (server mode)
	PocketIDAPIKey string // Pocket ID admin API key for fetching user/group data
	PocketIDAPIURL string // Pocket ID API base URL (defaults to IssuerURL)

	// Session persistence (server mode)
	SessionStateFile string // Path to JSON file for persisting grace sessions across restarts

	// Server-side client config overrides (server mode)
	ClientBreakglassPasswordType string // Override client's breakglass password type
	ClientBreakglassRotationDays int    // Override client's breakglass rotation days
	ClientTokenCacheEnabled      *bool  // Override client's token cache setting (nil = unset)

	// Token cache settings (client mode)
	TokenCacheEnabled  bool   // Whether token caching is enabled (default true)
	TokenCacheDir      string // Directory for cached tokens (default /run/pocketid)
	TokenCacheIssuer   string // OIDC issuer URL for local JWT validation
	TokenCacheClientID string // OIDC client ID for aud verification
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

	graceSec := envOrDefaultInt("PAM_POCKETID_GRACE_PERIOD", 0)
	cfg.GracePeriod = time.Duration(graceSec) * time.Second

	cfg.OneTapMaxAge = time.Duration(envOrDefaultInt("PAM_POCKETID_ONETAP_MAX_AGE", 7200)) * time.Second // default 2h

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

	// Enforce maximum grace period to limit trust window
	if cfg.GracePeriod > 24*time.Hour {
		return nil, fmt.Errorf("PAM_POCKETID_GRACE_PERIOD must not exceed 86400 seconds (24 hours)")
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
		log.Printf("SECURITY WARNING: PAM_POCKETID_EXTERNAL_URL uses HTTP — session cookies will be sent in cleartext. Use HTTPS in production.")
	}

	cfg.DefaultHistoryPageSize = envOrDefaultInt("PAM_POCKETID_HISTORY_PAGE_SIZE", 5)
	validPageSizes := map[int]bool{5: true, 10: true, 25: true, 50: true, 100: true, 500: true, 1000: true}
	if !validPageSizes[cfg.DefaultHistoryPageSize] {
		cfg.DefaultHistoryPageSize = 5
	}

	cfg.NotifyCommand = os.Getenv("PAM_POCKETID_NOTIFY_COMMAND")

	// Additional env var prefixes to pass through to the notify command.
	// Comma-separated list of prefixes, e.g., "APPRISE_,TELEGRAM_,NTFY_".
	if v := os.Getenv("PAM_POCKETID_NOTIFY_ENV"); v != "" {
		for _, prefix := range strings.Split(v, ",") {
			prefix = strings.TrimSpace(prefix)
			if prefix != "" {
				cfg.NotifyEnvPassthrough = append(cfg.NotifyEnvPassthrough, prefix)
			}
		}
	}

	cfg.NotifyUsersFile = os.Getenv("PAM_POCKETID_NOTIFY_USERS_FILE")
	if cfg.NotifyUsersFile != "" && !strings.HasPrefix(cfg.NotifyUsersFile, "/") {
		return nil, fmt.Errorf("PAM_POCKETID_NOTIFY_USERS_FILE must be an absolute path (got %q)", cfg.NotifyUsersFile)
	}

	// PAM_POCKETID_NOTIFY_USERS: inline JSON map of username → notification URLs.
	// Takes precedence over NOTIFY_USERS_FILE when both are set.
	if v := os.Getenv("PAM_POCKETID_NOTIFY_USERS"); v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.NotifyUsers); err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_NOTIFY_USERS: %w", err)
		}
	}

	cfg.NotifyWebhookURL = os.Getenv("PAM_POCKETID_NOTIFY_WEBHOOK_URL")

	// PAM_POCKETID_WEBHOOKS: inline JSON array of WebhookConfig objects.
	if v := os.Getenv("PAM_POCKETID_WEBHOOKS"); v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.Webhooks); err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_WEBHOOKS: %w", err)
		}
	}
	// PAM_POCKETID_WEBHOOKS_FILE: path to a JSON file containing a WebhookConfig array.
	if v := os.Getenv("PAM_POCKETID_WEBHOOKS_FILE"); v != "" {
		f, err := os.OpenFile(v, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_WEBHOOKS_FILE: %w", err)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_WEBHOOKS_FILE: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("PAM_POCKETID_WEBHOOKS_FILE: not a regular file")
		}
		if info.Size() > 65536 {
			return nil, fmt.Errorf("PAM_POCKETID_WEBHOOKS_FILE: file too large (max 64KB)")
		}
		data, err := io.ReadAll(io.LimitReader(f, 65536))
		if err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_WEBHOOKS_FILE: %w", err)
		}
		if err := json.Unmarshal(data, &cfg.Webhooks); err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_WEBHOOKS_FILE: %w", err)
		}
	}
	// Backward compat: treat the legacy single-URL env var as a raw webhook
	// when no explicit webhook list has been configured.
	if cfg.NotifyWebhookURL != "" && len(cfg.Webhooks) == 0 {
		cfg.Webhooks = append(cfg.Webhooks, WebhookConfig{URL: cfg.NotifyWebhookURL, Format: "raw"})
	}

	// Warn about likely misconfigurations: per-user config or env passthrough
	// without a notify command means those settings have no effect.
	if cfg.NotifyCommand == "" {
		if cfg.NotifyUsersFile != "" {
			log.Printf("WARNING: PAM_POCKETID_NOTIFY_USERS_FILE is set but PAM_POCKETID_NOTIFY_COMMAND is empty — per-user routing will have no effect")
		}
		if cfg.NotifyUsers != nil {
			log.Printf("WARNING: PAM_POCKETID_NOTIFY_USERS is set but PAM_POCKETID_NOTIFY_COMMAND is empty — per-user routing will have no effect")
		}
		if len(cfg.NotifyEnvPassthrough) > 0 {
			log.Printf("WARNING: PAM_POCKETID_NOTIFY_ENV is set but PAM_POCKETID_NOTIFY_COMMAND is empty — env passthrough will have no effect")
		}
	}

	cfg.SessionStateFile = os.Getenv("PAM_POCKETID_SESSION_STATE_FILE")

	// Host registry file: if explicitly set, use it. Otherwise, if SESSION_STATE_FILE
	// is set, default to the same directory + "hosts.json".
	cfg.HostRegistryFile = os.Getenv("PAM_POCKETID_HOST_REGISTRY_FILE")
	if cfg.HostRegistryFile == "" && cfg.SessionStateFile != "" {
		dir := cfg.SessionStateFile[:strings.LastIndex(cfg.SessionStateFile, "/")+1]
		if dir != "" {
			cfg.HostRegistryFile = dir + "hosts.json"
		}
	}

	cfg.EscrowCommand = os.Getenv("PAM_POCKETID_ESCROW_COMMAND")

	// Additional env var prefixes to pass through to the escrow command.
	// Comma-separated list of prefixes, e.g., "AWS_,VAULT_,OP_".
	// Only env vars matching these prefixes are passed; all others are stripped
	// to prevent leaking server secrets (CLIENT_SECRET, SHARED_SECRET, etc.).
	if v := os.Getenv("PAM_POCKETID_ESCROW_ENV"); v != "" {
		for _, prefix := range strings.Split(v, ",") {
			prefix = strings.TrimSpace(prefix)
			if prefix != "" {
				cfg.EscrowEnvPassthrough = append(cfg.EscrowEnvPassthrough, prefix)
			}
		}
	}

	// Native escrow backend (alternative to EscrowCommand)
	cfg.EscrowBackend = os.Getenv("PAM_POCKETID_ESCROW_BACKEND")
	if cfg.EscrowBackend != "" {
		switch cfg.EscrowBackend {
		case "1password-connect", "vault", "bitwarden", "infisical":
			// valid
		default:
			return nil, fmt.Errorf("PAM_POCKETID_ESCROW_BACKEND must be one of: 1password-connect, vault, bitwarden, infisical")
		}
		cfg.EscrowURL = os.Getenv("PAM_POCKETID_ESCROW_URL")
		cfg.EscrowAuthID = os.Getenv("PAM_POCKETID_ESCROW_AUTH_ID")
		cfg.EscrowAuthSecret = os.Getenv("PAM_POCKETID_ESCROW_AUTH_SECRET")
		if secretFile := os.Getenv("PAM_POCKETID_ESCROW_AUTH_SECRET_FILE"); secretFile != "" && cfg.EscrowAuthSecret == "" {
			data, err := os.ReadFile(secretFile)
			if err != nil {
				return nil, fmt.Errorf("PAM_POCKETID_ESCROW_AUTH_SECRET_FILE: %w", err)
			}
			cfg.EscrowAuthSecret = strings.TrimSpace(string(data))
		}
		cfg.EscrowPath = os.Getenv("PAM_POCKETID_ESCROW_PATH")
		if cfg.EscrowURL == "" {
			return nil, fmt.Errorf("PAM_POCKETID_ESCROW_URL is required when ESCROW_BACKEND is set")
		}
		if cfg.EscrowAuthSecret == "" {
			return nil, fmt.Errorf("PAM_POCKETID_ESCROW_AUTH_SECRET (or _FILE) is required when ESCROW_BACKEND is set")
		}
	}

	cfg.EscrowLinkTemplate = os.Getenv("PAM_POCKETID_ESCROW_LINK_TEMPLATE")
	cfg.EscrowLinkLabel = os.Getenv("PAM_POCKETID_ESCROW_LINK_LABEL")
	if cfg.EscrowLinkLabel == "" && cfg.EscrowLinkTemplate != "" {
		cfg.EscrowLinkLabel = "View password"
	}

	if v := os.Getenv("PAM_POCKETID_ADMIN_GROUPS"); v != "" {
		for _, g := range strings.Split(v, ",") {
			g = strings.TrimSpace(g)
			if g != "" {
				cfg.AdminGroups = append(cfg.AdminGroups, g)
			}
		}
	}

	if v := os.Getenv("PAM_POCKETID_ADMIN_APPROVAL_HOSTS"); v != "" {
		for _, h := range strings.Split(v, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				cfg.AdminApprovalHosts = append(cfg.AdminApprovalHosts, h)
			}
		}
	}

	if v := os.Getenv("PAM_POCKETID_API_KEYS"); v != "" {
		for _, k := range strings.Split(v, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				cfg.APIKeys = append(cfg.APIKeys, k)
			}
		}
	}

	cfg.PocketIDAPIKey = os.Getenv("PAM_POCKETID_POCKETID_API_KEY")
	cfg.PocketIDAPIURL = os.Getenv("PAM_POCKETID_POCKETID_API_URL")
	if cfg.PocketIDAPIURL == "" {
		cfg.PocketIDAPIURL = cfg.IssuerURL // same host
	}

	if v := os.Getenv("PAM_POCKETID_BREAKGLASS_ROTATE_BEFORE"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_BREAKGLASS_ROTATE_BEFORE must be RFC3339 format (e.g., 2025-01-15T00:00:00Z): %w", err)
		}
		cfg.BreakglassRotateBefore = t
	}

	// Server-side client config overrides
	cfg.ClientBreakglassPasswordType = os.Getenv("PAM_POCKETID_CLIENT_BREAKGLASS_PASSWORD_TYPE")
	if cfg.ClientBreakglassPasswordType != "" {
		switch cfg.ClientBreakglassPasswordType {
		case "random", "passphrase", "alphanumeric":
			// valid
		default:
			return nil, fmt.Errorf("PAM_POCKETID_CLIENT_BREAKGLASS_PASSWORD_TYPE must be one of: random, passphrase, alphanumeric")
		}
	}
	if v := os.Getenv("PAM_POCKETID_CLIENT_BREAKGLASS_ROTATION_DAYS"); v != "" {
		days, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_CLIENT_BREAKGLASS_ROTATION_DAYS must be an integer: %w", err)
		}
		if days < 1 {
			return nil, fmt.Errorf("PAM_POCKETID_CLIENT_BREAKGLASS_ROTATION_DAYS must be at least 1")
		}
		cfg.ClientBreakglassRotationDays = days
	}
	if v := os.Getenv("PAM_POCKETID_CLIENT_TOKEN_CACHE"); v != "" {
		switch v {
		case "true", "1":
			b := true
			cfg.ClientTokenCacheEnabled = &b
		case "false", "0":
			b := false
			cfg.ClientTokenCacheEnabled = &b
		default:
			log.Printf("WARNING: PAM_POCKETID_CLIENT_TOKEN_CACHE has unrecognized value %q (expected true/false/1/0) — ignoring", v)
		}
	}

	// PAM_POCKETID_CLIENT_CONFIG: JSON blob to set multiple client overrides at once.
	// Takes precedence over the individual CLIENT_BREAKGLASS_* and CLIENT_TOKEN_CACHE vars.
	// Format: {"breakglass_password_type":"random","breakglass_rotation_days":90,"token_cache":true}
	if v := os.Getenv("PAM_POCKETID_CLIENT_CONFIG"); v != "" {
		var cc struct {
			BreakglassPasswordType string `json:"breakglass_password_type"`
			BreakglassRotationDays int    `json:"breakglass_rotation_days"`
			TokenCache             *bool  `json:"token_cache"`
		}
		if err := json.Unmarshal([]byte(v), &cc); err != nil {
			return nil, fmt.Errorf("PAM_POCKETID_CLIENT_CONFIG: %w", err)
		}
		if cc.BreakglassPasswordType != "" {
			switch cc.BreakglassPasswordType {
			case "random", "passphrase", "alphanumeric":
				cfg.ClientBreakglassPasswordType = cc.BreakglassPasswordType
			default:
				return nil, fmt.Errorf("PAM_POCKETID_CLIENT_CONFIG: breakglass_password_type must be one of: random, passphrase, alphanumeric")
			}
		}
		if cc.BreakglassRotationDays > 0 {
			cfg.ClientBreakglassRotationDays = cc.BreakglassRotationDays
		}
		if cc.TokenCache != nil {
			cfg.ClientTokenCacheEnabled = cc.TokenCache
		}
	}

	// Best-effort: clear secrets from environment to reduce exposure window.
	// Note: this does NOT scrub /proc/PID/environ on Linux (the initial
	// environment snapshot is immutable), but it prevents os.Getenv from
	// returning the values and removes them from child process inheritance.
	os.Unsetenv("PAM_POCKETID_SHARED_SECRET")
	os.Unsetenv("PAM_POCKETID_CLIENT_SECRET")
	os.Unsetenv("PAM_POCKETID_POCKETID_API_KEY")
	os.Unsetenv("PAM_POCKETID_API_KEYS")
	os.Unsetenv("PAM_POCKETID_ESCROW_AUTH_SECRET")

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

	if cfg.ServerURL == "" && !clientConfigAllowNoServer {
		return nil, fmt.Errorf("PAM_POCKETID_SERVER_URL is required")
	}

	if cfg.ServerURL != "" {
		// Validate ServerURL scheme to prevent SSRF via malicious config
		if !strings.HasPrefix(cfg.ServerURL, "https://") && !strings.HasPrefix(cfg.ServerURL, "http://") {
			return nil, fmt.Errorf("PAM_POCKETID_SERVER_URL must start with https:// or http://")
		}

		// Reject URLs with embedded credentials (prevents secret leakage in logs/errors)
		if u, err := url.Parse(cfg.ServerURL); err == nil && u.User != nil {
			return nil, fmt.Errorf("PAM_POCKETID_SERVER_URL must not contain embedded credentials")
		}

		// Warn if ServerURL uses plain HTTP (shared secret and break-glass passwords will be in cleartext)
		if strings.HasPrefix(cfg.ServerURL, "http://") {
			fmt.Fprintf(os.Stderr, "pam-pocketid: SECURITY WARNING: PAM_POCKETID_SERVER_URL uses HTTP — shared secret transmitted in cleartext\n")
		}
	}

	// Enforce poll interval bounds to prevent tight-loop DoS
	if cfg.PollInterval < 500*time.Millisecond {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: PAM_POCKETID_POLL_MS clamped to minimum 500ms\n")
		cfg.PollInterval = 500 * time.Millisecond
	}
	if cfg.PollInterval > 30*time.Second {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: PAM_POCKETID_POLL_MS clamped to maximum 30s\n")
		cfg.PollInterval = 30 * time.Second
	}

	// Enforce timeout bounds to prevent indefinite PAM session blocking
	if cfg.Timeout < 10*time.Second {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: PAM_POCKETID_TIMEOUT clamped to minimum 10s\n")
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Timeout > 600*time.Second {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: PAM_POCKETID_TIMEOUT clamped to maximum 600s\n")
		cfg.Timeout = 600 * time.Second
	}

	// Enforce minimum SharedSecret length on client side (mirrors server check)
	if cfg.SharedSecret != "" && len(cfg.SharedSecret) < 16 {
		return nil, fmt.Errorf("PAM_POCKETID_SHARED_SECRET must be at least 16 characters")
	}

	// Break-glass settings
	breakglassEnabled, err := configValueBool("PAM_POCKETID_BREAKGLASS_ENABLED", fileVars, true)
	if err != nil {
		return nil, err
	}
	cfg.BreakglassEnabled = breakglassEnabled
	cfg.BreakglassFile = configValue("PAM_POCKETID_BREAKGLASS_FILE", fileVars)
	if cfg.BreakglassFile == "" {
		cfg.BreakglassFile = "/etc/pam-pocketid-breakglass"
	}
	// Require absolute path to prevent writing to user-controlled cwd
	if !strings.HasPrefix(cfg.BreakglassFile, "/") {
		return nil, fmt.Errorf("PAM_POCKETID_BREAKGLASS_FILE must be an absolute path (got %q)", cfg.BreakglassFile)
	}
	cfg.BreakglassRotationDays = configValueInt("PAM_POCKETID_BREAKGLASS_ROTATION_DAYS", fileVars, 90)
	if cfg.BreakglassRotationDays < 1 {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: PAM_POCKETID_BREAKGLASS_ROTATION_DAYS clamped to minimum 1\n")
		cfg.BreakglassRotationDays = 1
	}
	// Clamp to prevent time.Duration overflow (int64 nanoseconds max ~292 years ≈ 106751 days)
	if cfg.BreakglassRotationDays > 3650 {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: PAM_POCKETID_BREAKGLASS_ROTATION_DAYS clamped to maximum 3650\n")
		cfg.BreakglassRotationDays = 3650
	}
	cfg.BreakglassPasswordType = configValue("PAM_POCKETID_BREAKGLASS_PASSWORD_TYPE", fileVars)
	if cfg.BreakglassPasswordType == "" {
		cfg.BreakglassPasswordType = "random"
	}
	switch cfg.BreakglassPasswordType {
	case "random", "passphrase", "alphanumeric":
		// valid
	default:
		return nil, fmt.Errorf("PAM_POCKETID_BREAKGLASS_PASSWORD_TYPE must be one of: random, passphrase, alphanumeric")
	}

	// Token cache settings
	tokenCacheEnabled, err := configValueBool("PAM_POCKETID_TOKEN_CACHE", fileVars, true)
	if err != nil {
		return nil, err
	}
	cfg.TokenCacheEnabled = tokenCacheEnabled
	cfg.TokenCacheDir = configValue("PAM_POCKETID_TOKEN_CACHE_DIR", fileVars)
	if cfg.TokenCacheDir == "" {
		cfg.TokenCacheDir = "/run/pocketid"
	}
	if !strings.HasPrefix(cfg.TokenCacheDir, "/") {
		return nil, fmt.Errorf("PAM_POCKETID_TOKEN_CACHE_DIR must be an absolute path (got %q)", cfg.TokenCacheDir)
	}
	cfg.TokenCacheIssuer = configValue("PAM_POCKETID_ISSUER_URL", fileVars)
	cfg.TokenCacheClientID = configValue("PAM_POCKETID_CLIENT_ID", fileVars)

	// Graceful degradation: disable cache if issuer/clientID are missing
	if cfg.TokenCacheEnabled && (cfg.TokenCacheIssuer == "" || cfg.TokenCacheClientID == "") {
		cfg.TokenCacheEnabled = false
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
	if uid, ok := fileOwnerUID(info); !ok {
		fmt.Fprintf(os.Stderr, "pam-pocketid: ERROR: cannot determine owner of %s — refusing to load\n", path)
		return vars
	} else if uid != 0 {
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

// configValueBool returns the env var as bool if set, otherwise the config file
// value as bool, otherwise the default.
// Accepts "true", "1", "yes", "on" as true and "false", "0", "no", "off", "" as false.
// Returns an error for any other value.
func configValueBool(key string, fileVars map[string]string, def bool) (bool, error) {
	v := configValue(key, fileVars)
	if v == "" {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return def, fmt.Errorf("%s: unrecognized boolean value %q (use true/false/yes/no/1/0)", key, v)
	}
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
