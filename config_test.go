package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
