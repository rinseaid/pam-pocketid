package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func init() {
	// Tests run as non-root, so override the ownership check to always return root (uid 0).
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) {
		return 0, true
	}
}

func TestLoadConfigFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("basic key-value", func(t *testing.T) {
		path := filepath.Join(dir, "basic.conf")
		os.WriteFile(path, []byte("KEY1=value1\nKEY2=value2\n"), 0600)
		vars := loadConfigFile(path)
		if vars["KEY1"] != "value1" || vars["KEY2"] != "value2" {
			t.Errorf("got %v", vars)
		}
	})

	t.Run("comments and blank lines", func(t *testing.T) {
		path := filepath.Join(dir, "comments.conf")
		os.WriteFile(path, []byte("# comment\n\nKEY=val\n  # indented comment\n"), 0600)
		vars := loadConfigFile(path)
		if len(vars) != 1 || vars["KEY"] != "val" {
			t.Errorf("got %v", vars)
		}
	})

	t.Run("quoted values", func(t *testing.T) {
		path := filepath.Join(dir, "quoted.conf")
		os.WriteFile(path, []byte("A=\"double quoted\"\nB='single quoted'\n"), 0600)
		vars := loadConfigFile(path)
		if vars["A"] != "double quoted" || vars["B"] != "single quoted" {
			t.Errorf("got %v", vars)
		}
	})

	t.Run("whitespace trimming", func(t *testing.T) {
		path := filepath.Join(dir, "spaces.conf")
		os.WriteFile(path, []byte("  KEY  =  value  \n"), 0600)
		vars := loadConfigFile(path)
		if vars["KEY"] != "value" {
			t.Errorf("got %q", vars["KEY"])
		}
	})

	t.Run("missing file returns empty map", func(t *testing.T) {
		vars := loadConfigFile("/nonexistent/path")
		if len(vars) != 0 {
			t.Errorf("expected empty map, got %v", vars)
		}
	})

	t.Run("lines without = are skipped", func(t *testing.T) {
		path := filepath.Join(dir, "noequals.conf")
		os.WriteFile(path, []byte("not a key value pair\nKEY=val\n"), 0600)
		vars := loadConfigFile(path)
		if len(vars) != 1 || vars["KEY"] != "val" {
			t.Errorf("got %v", vars)
		}
	})
}

func TestLoadClientConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "pam-pocketid.conf")

	// Save and restore the original DefaultConfigPath isn't possible since
	// it's a const, so we test via loadConfigFile + configValue directly.

	t.Run("env var takes precedence over file", func(t *testing.T) {
		fileVars := map[string]string{
			"PAM_POCKETID_SERVER_URL": "http://from-file:8090",
		}
		t.Setenv("PAM_POCKETID_SERVER_URL", "http://from-env:8090")
		got := configValue("PAM_POCKETID_SERVER_URL", fileVars)
		if got != "http://from-env:8090" {
			t.Errorf("expected env value, got %q", got)
		}
	})

	t.Run("file value used when env not set", func(t *testing.T) {
		fileVars := map[string]string{
			"PAM_POCKETID_SERVER_URL": "http://from-file:8090",
		}
		// Ensure env var is not set
		os.Unsetenv("PAM_POCKETID_SERVER_URL")
		got := configValue("PAM_POCKETID_SERVER_URL", fileVars)
		if got != "http://from-file:8090" {
			t.Errorf("expected file value, got %q", got)
		}
	})

	t.Run("configValueInt precedence", func(t *testing.T) {
		fileVars := map[string]string{"PAM_POCKETID_POLL_MS": "5000"}

		// No env var — use file
		os.Unsetenv("PAM_POCKETID_POLL_MS")
		got := configValueInt("PAM_POCKETID_POLL_MS", fileVars, 2000)
		if got != 5000 {
			t.Errorf("expected 5000, got %d", got)
		}

		// With env var — use env
		t.Setenv("PAM_POCKETID_POLL_MS", "3000")
		got = configValueInt("PAM_POCKETID_POLL_MS", fileVars, 2000)
		if got != 3000 {
			t.Errorf("expected 3000, got %d", got)
		}

		// Neither set — use default
		os.Unsetenv("PAM_POCKETID_POLL_MS")
		got = configValueInt("PAM_POCKETID_POLL_MS", map[string]string{}, 2000)
		if got != 2000 {
			t.Errorf("expected 2000, got %d", got)
		}
	})

	_ = confPath // used in future integration tests
}

func TestPollIntervalBounds(t *testing.T) {
	t.Run("too low gets clamped to 500ms", func(t *testing.T) {
		t.Setenv("PAM_POCKETID_SERVER_URL", "http://localhost:8090")
		t.Setenv("PAM_POCKETID_POLL_MS", "100")
		os.Unsetenv("PAM_POCKETID_SHARED_SECRET")
		cfg, err := LoadClientConfig()
		if err != nil {
			t.Fatalf("LoadClientConfig: %v", err)
		}
		if cfg.PollInterval != 500*time.Millisecond {
			t.Errorf("PollInterval = %v, want 500ms", cfg.PollInterval)
		}
	})

	t.Run("too high gets clamped to 30s", func(t *testing.T) {
		t.Setenv("PAM_POCKETID_SERVER_URL", "http://localhost:8090")
		t.Setenv("PAM_POCKETID_POLL_MS", "60000")
		os.Unsetenv("PAM_POCKETID_SHARED_SECRET")
		cfg, err := LoadClientConfig()
		if err != nil {
			t.Fatalf("LoadClientConfig: %v", err)
		}
		if cfg.PollInterval != 30*time.Second {
			t.Errorf("PollInterval = %v, want 30s", cfg.PollInterval)
		}
	})
}

func TestServerURLRejectsCredentials(t *testing.T) {
	t.Setenv("PAM_POCKETID_SERVER_URL", "http://user:pass@localhost:8090")
	os.Unsetenv("PAM_POCKETID_SHARED_SECRET")
	_, err := LoadClientConfig()
	if err == nil {
		t.Error("expected error for URL with embedded credentials")
	}
}

func TestBOMInConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.conf")
	// UTF-8 BOM + KEY=VALUE
	os.WriteFile(path, []byte("\xef\xbb\xbfKEY=value\n"), 0600)
	vars := loadConfigFile(path)
	if vars["KEY"] != "value" {
		t.Errorf("BOM-prefixed file: KEY = %q, want %q", vars["KEY"], "value")
	}
}

func TestMandatorySharedSecret(t *testing.T) {
	t.Setenv("PAM_POCKETID_ISSUER_URL", "https://id.example.com")
	t.Setenv("PAM_POCKETID_CLIENT_ID", "test")
	t.Setenv("PAM_POCKETID_CLIENT_SECRET", "secret")
	t.Setenv("PAM_POCKETID_EXTERNAL_URL", "https://sudo.example.com")
	os.Unsetenv("PAM_POCKETID_SHARED_SECRET")
	os.Unsetenv("PAM_POCKETID_INSECURE")

	_, err := LoadServerConfig()
	if err == nil {
		t.Error("expected error when shared secret is not set")
	}

	// With PAM_POCKETID_INSECURE=true, it should succeed
	t.Setenv("PAM_POCKETID_INSECURE", "true")
	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig with INSECURE=true: %v", err)
	}
	if cfg.SharedSecret != "" {
		t.Error("SharedSecret should be empty")
	}
}

func TestSharedSecretMinLength(t *testing.T) {
	t.Setenv("PAM_POCKETID_ISSUER_URL", "https://id.example.com")
	t.Setenv("PAM_POCKETID_CLIENT_ID", "test")
	t.Setenv("PAM_POCKETID_CLIENT_SECRET", "secret")
	t.Setenv("PAM_POCKETID_EXTERNAL_URL", "https://sudo.example.com")
	os.Unsetenv("PAM_POCKETID_INSECURE")

	// Too short (15 chars)
	t.Setenv("PAM_POCKETID_SHARED_SECRET", "short-secret-15")
	_, err := LoadServerConfig()
	if err == nil {
		t.Error("expected error for shared secret shorter than 16 chars")
	}

	// Exactly 16 chars — should succeed
	t.Setenv("PAM_POCKETID_SHARED_SECRET", "exactly16chars!!")
	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig with 16-char secret: %v", err)
	}
	if cfg.SharedSecret != "exactly16chars!!" {
		t.Error("SharedSecret not set correctly")
	}
}

func TestIssuerURLValidation(t *testing.T) {
	t.Setenv("PAM_POCKETID_CLIENT_ID", "test")
	t.Setenv("PAM_POCKETID_CLIENT_SECRET", "secret")
	t.Setenv("PAM_POCKETID_EXTERNAL_URL", "https://sudo.example.com")
	t.Setenv("PAM_POCKETID_SHARED_SECRET", "test-secret-that-is-long-enough")

	// Invalid scheme
	t.Setenv("PAM_POCKETID_ISSUER_URL", "ftp://id.example.com")
	_, err := LoadServerConfig()
	if err == nil {
		t.Error("expected error for ftp:// issuer URL")
	}

	// Embedded credentials
	t.Setenv("PAM_POCKETID_ISSUER_URL", "https://user:pass@id.example.com")
	_, err = LoadServerConfig()
	if err == nil {
		t.Error("expected error for issuer URL with embedded credentials")
	}
}

func TestExternalURLRejectsCredentials(t *testing.T) {
	t.Setenv("PAM_POCKETID_ISSUER_URL", "https://id.example.com")
	t.Setenv("PAM_POCKETID_CLIENT_ID", "test")
	t.Setenv("PAM_POCKETID_CLIENT_SECRET", "secret")
	t.Setenv("PAM_POCKETID_SHARED_SECRET", "test-secret-that-is-long-enough")

	t.Setenv("PAM_POCKETID_EXTERNAL_URL", "https://admin:secret@sudo.example.com")
	_, err := LoadServerConfig()
	if err == nil {
		t.Error("expected error for external URL with embedded credentials")
	}
}

func TestClientTimeoutBounds(t *testing.T) {
	t.Setenv("PAM_POCKETID_SERVER_URL", "http://localhost:8090")
	os.Unsetenv("PAM_POCKETID_SHARED_SECRET")

	// Too low gets clamped to 10s
	t.Setenv("PAM_POCKETID_TIMEOUT", "1")
	cfg, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
	}

	// Too high gets clamped to 600s
	t.Setenv("PAM_POCKETID_TIMEOUT", "99999")
	cfg, err = LoadClientConfig()
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}
	if cfg.Timeout != 600*time.Second {
		t.Errorf("Timeout = %v, want 600s", cfg.Timeout)
	}
}

// serverConfigBase sets the minimum env vars required for LoadServerConfig.
func serverConfigBase(t *testing.T) {
	t.Helper()
	t.Setenv("PAM_POCKETID_ISSUER_URL", "https://id.example.com")
	t.Setenv("PAM_POCKETID_CLIENT_ID", "test")
	t.Setenv("PAM_POCKETID_CLIENT_SECRET", "secret")
	t.Setenv("PAM_POCKETID_EXTERNAL_URL", "https://sudo.example.com")
	t.Setenv("PAM_POCKETID_SHARED_SECRET", "test-secret-that-is-long-enough")
}

// Note: LoadServerConfig clears PAM_POCKETID_CLIENT_SECRET and
// PAM_POCKETID_SHARED_SECRET after reading them (security hygiene).
// Each sub-test that calls LoadServerConfig must call serverConfigBase(t)
// on its own t so that t.Setenv re-registers a restore for these vars.

func TestNotifyUsersInlineJSON(t *testing.T) {
	t.Run("valid JSON parsed into map", func(t *testing.T) {
		serverConfigBase(t)
		t.Setenv("PAM_POCKETID_NOTIFY_USERS", `{"alice":"tgram://bot/111","*":"slack://fallback"}`)
		cfg, err := LoadServerConfig()
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.NotifyUsers["alice"] != "tgram://bot/111" {
			t.Errorf("alice URL = %q", cfg.NotifyUsers["alice"])
		}
		if cfg.NotifyUsers["*"] != "slack://fallback" {
			t.Errorf("wildcard URL = %q", cfg.NotifyUsers["*"])
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		serverConfigBase(t)
		t.Setenv("PAM_POCKETID_NOTIFY_USERS", `not json`)
		_, err := LoadServerConfig()
		if err == nil {
			t.Error("expected error for invalid NOTIFY_USERS JSON")
		}
	})

	t.Run("unset means nil map", func(t *testing.T) {
		serverConfigBase(t)
		os.Unsetenv("PAM_POCKETID_NOTIFY_USERS")
		cfg, err := LoadServerConfig()
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.NotifyUsers != nil {
			t.Errorf("expected nil NotifyUsers, got %v", cfg.NotifyUsers)
		}
	})
}

func TestClientConfigJSON(t *testing.T) {
	t.Run("sets all fields via JSON", func(t *testing.T) {
		serverConfigBase(t)
		t.Setenv("PAM_POCKETID_CLIENT_CONFIG", `{"breakglass_password_type":"passphrase","breakglass_rotation_days":90,"token_cache":true}`)
		cfg, err := LoadServerConfig()
		if err != nil {
			t.Fatalf("LoadServerConfig: %v", err)
		}
		if cfg.ClientBreakglassPasswordType != "passphrase" {
			t.Errorf("PasswordType = %q, want passphrase", cfg.ClientBreakglassPasswordType)
		}
		if cfg.ClientBreakglassRotationDays != 90 {
			t.Errorf("RotationDays = %d, want 90", cfg.ClientBreakglassRotationDays)
		}
		if cfg.ClientTokenCacheEnabled == nil || !*cfg.ClientTokenCacheEnabled {
			t.Error("TokenCacheEnabled should be true")
		}
	})

	t.Run("invalid password type returns error", func(t *testing.T) {
		serverConfigBase(t)
		t.Setenv("PAM_POCKETID_CLIENT_CONFIG", `{"breakglass_password_type":"invalid"}`)
		_, err := LoadServerConfig()
		if err == nil {
			t.Error("expected error for invalid breakglass_password_type")
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		serverConfigBase(t)
		t.Setenv("PAM_POCKETID_CLIENT_CONFIG", `not json`)
		_, err := LoadServerConfig()
		if err == nil {
			t.Error("expected error for invalid CLIENT_CONFIG JSON")
		}
	})
}

func TestEscrowBackendValidation(t *testing.T) {
	t.Run("invalid backend returns error", func(t *testing.T) {
		serverConfigBase(t)
		t.Setenv("PAM_POCKETID_ESCROW_BACKEND", "s3")
		_, err := LoadServerConfig()
		if err == nil {
			t.Error("expected error for unknown escrow backend")
		}
	})

	t.Run("valid backend without URL returns error", func(t *testing.T) {
		serverConfigBase(t)
		t.Setenv("PAM_POCKETID_ESCROW_BACKEND", "vault")
		os.Unsetenv("PAM_POCKETID_ESCROW_URL")
		t.Setenv("PAM_POCKETID_ESCROW_AUTH_SECRET", "tok")
		_, err := LoadServerConfig()
		if err == nil {
			t.Error("expected error when ESCROW_URL is missing")
		}
	})

	t.Run("valid backend without auth secret returns error", func(t *testing.T) {
		serverConfigBase(t)
		t.Setenv("PAM_POCKETID_ESCROW_BACKEND", "vault")
		t.Setenv("PAM_POCKETID_ESCROW_URL", "http://vault:8200")
		os.Unsetenv("PAM_POCKETID_ESCROW_AUTH_SECRET")
		os.Unsetenv("PAM_POCKETID_ESCROW_AUTH_SECRET_FILE")
		_, err := LoadServerConfig()
		if err == nil {
			t.Error("expected error when ESCROW_AUTH_SECRET is missing")
		}
	})

	t.Run("all valid backends accepted", func(t *testing.T) {
		for _, backend := range []string{"1password-connect", "vault", "bitwarden", "infisical"} {
			t.Run(backend, func(t *testing.T) {
				serverConfigBase(t)
				t.Setenv("PAM_POCKETID_ESCROW_BACKEND", backend)
				t.Setenv("PAM_POCKETID_ESCROW_URL", "http://backend:8080")
				t.Setenv("PAM_POCKETID_ESCROW_AUTH_SECRET", "mysecret")
				cfg, err := LoadServerConfig()
				if err != nil {
					t.Fatalf("LoadServerConfig for backend %q: %v", backend, err)
				}
				if cfg.EscrowBackend != backend {
					t.Errorf("EscrowBackend = %q, want %q", cfg.EscrowBackend, backend)
				}
			})
		}
	})
}
