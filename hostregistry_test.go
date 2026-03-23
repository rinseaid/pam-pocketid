package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestHostRegistryBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")

	r := NewHostRegistry(path)

	// Empty registry should not be enabled
	if r.IsEnabled() {
		t.Error("empty registry should not be enabled")
	}

	// Empty registry accepts anything (backward compat)
	if !r.ValidateHost("any-host", "any-secret") {
		t.Error("empty registry should accept any host")
	}
	if !r.IsUserAuthorized("any-host", "any-user") {
		t.Error("empty registry should authorize any user")
	}

	// Add a host
	secret, err := r.AddHost("host1.example.com", []string{"alice", "bob"}, "")
	if err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if secret == "" {
		t.Error("expected non-empty secret")
	}
	if len(secret) != 64 { // 32 bytes hex-encoded
		t.Errorf("expected 64-char hex secret, got %d chars", len(secret))
	}

	// Now registry should be enabled
	if !r.IsEnabled() {
		t.Error("registry should be enabled after adding a host")
	}

	// Validate the host with correct secret
	if !r.ValidateHost("host1.example.com", secret) {
		t.Error("ValidateHost should succeed with correct secret")
	}

	// Validate with wrong secret
	if r.ValidateHost("host1.example.com", "wrong-secret") {
		t.Error("ValidateHost should fail with wrong secret")
	}

	// Validate unregistered host
	if r.ValidateHost("unknown.example.com", secret) {
		t.Error("ValidateHost should fail for unregistered host")
	}

	// User authorization
	if !r.IsUserAuthorized("host1.example.com", "alice") {
		t.Error("alice should be authorized on host1")
	}
	if !r.IsUserAuthorized("host1.example.com", "bob") {
		t.Error("bob should be authorized on host1")
	}
	if r.IsUserAuthorized("host1.example.com", "charlie") {
		t.Error("charlie should not be authorized on host1")
	}
	if r.IsUserAuthorized("unknown.example.com", "alice") {
		t.Error("alice should not be authorized on unknown host")
	}

	// Duplicate add should fail
	_, err = r.AddHost("host1.example.com", []string{"*"}, "")
	if err == nil {
		t.Error("duplicate AddHost should fail")
	}

	// List hosts
	hosts := r.RegisteredHosts()
	if len(hosts) != 1 || hosts[0] != "host1.example.com" {
		t.Errorf("RegisteredHosts: got %v", hosts)
	}

	// GetHost
	users, _, _, ok := r.GetHost("host1.example.com")
	if !ok {
		t.Error("GetHost should return true for registered host")
	}
	if len(users) != 2 || users[0] != "alice" || users[1] != "bob" {
		t.Errorf("GetHost users: got %v", users)
	}

	// HostsForUser
	aliceHosts := r.HostsForUser("alice")
	if len(aliceHosts) != 1 || aliceHosts[0] != "host1.example.com" {
		t.Errorf("HostsForUser(alice): got %v", aliceHosts)
	}
	charlieHosts := r.HostsForUser("charlie")
	if len(charlieHosts) != 0 {
		t.Errorf("HostsForUser(charlie): expected empty, got %v", charlieHosts)
	}

	// Verify persistence
	r2 := NewHostRegistry(path)
	if !r2.IsEnabled() {
		t.Error("reloaded registry should be enabled")
	}
	if !r2.ValidateHost("host1.example.com", secret) {
		t.Error("reloaded registry should validate with original secret")
	}
}

func TestHostRegistryWildcardUsers(t *testing.T) {
	r := NewHostRegistry("")
	r.hosts["wildcard-host"] = &RegisteredHost{
		Secret: "test-secret",
		Users:  []string{"*"},
	}

	if !r.IsUserAuthorized("wildcard-host", "anyone") {
		t.Error("wildcard should authorize any user")
	}
}

func TestHostRegistryRotateSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")

	r := NewHostRegistry(path)
	oldSecret, _ := r.AddHost("host1.example.com", []string{"*"}, "")

	newSecret, err := r.RotateSecret("host1.example.com")
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if newSecret == oldSecret {
		t.Error("rotated secret should differ from old secret")
	}

	// Old secret should no longer work
	if r.ValidateHost("host1.example.com", oldSecret) {
		t.Error("old secret should not validate after rotation")
	}
	if !r.ValidateHost("host1.example.com", newSecret) {
		t.Error("new secret should validate after rotation")
	}

	// Rotate nonexistent host
	_, err = r.RotateSecret("nonexistent.example.com")
	if err == nil {
		t.Error("RotateSecret should fail for nonexistent host")
	}
}

func TestHostRegistryRemoveHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")

	r := NewHostRegistry(path)
	r.AddHost("host1.example.com", []string{"*"}, "")

	err := r.RemoveHost("host1.example.com")
	if err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
	if r.IsEnabled() {
		t.Error("registry should not be enabled after removing the only host")
	}

	// Remove nonexistent host
	err = r.RemoveHost("nonexistent.example.com")
	if err == nil {
		t.Error("RemoveHost should fail for nonexistent host")
	}
}

func TestHostRegistryValidateAnyHost(t *testing.T) {
	r := NewHostRegistry("")
	r.hosts["host1"] = &RegisteredHost{Secret: "secret1", Users: []string{"*"}}
	r.hosts["host2"] = &RegisteredHost{Secret: "secret2", Users: []string{"*"}}

	if !r.ValidateAnyHost("secret1") {
		t.Error("ValidateAnyHost should match secret1")
	}
	if !r.ValidateAnyHost("secret2") {
		t.Error("ValidateAnyHost should match secret2")
	}
	if r.ValidateAnyHost("wrong") {
		t.Error("ValidateAnyHost should reject wrong secret")
	}
}

func TestHostRegistryPersistenceReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")

	// Create and populate
	r1 := NewHostRegistry(path)
	secret1, _ := r1.AddHost("host1.example.com", []string{"alice", "bob"}, "")
	secret2, _ := r1.AddHost("host2.example.com", []string{"*"}, "")

	// Reload from disk
	r2 := NewHostRegistry(path)

	// Verify all data persisted
	if !r2.ValidateHost("host1.example.com", secret1) {
		t.Error("host1 secret should survive reload")
	}
	if !r2.ValidateHost("host2.example.com", secret2) {
		t.Error("host2 secret should survive reload")
	}
	if !r2.IsUserAuthorized("host1.example.com", "alice") {
		t.Error("alice auth should survive reload")
	}
	if r2.IsUserAuthorized("host1.example.com", "charlie") {
		t.Error("charlie should not be authorized after reload")
	}
	if !r2.IsUserAuthorized("host2.example.com", "anyone") {
		t.Error("wildcard auth should survive reload")
	}
}

func TestHostRegistryMissingFile(t *testing.T) {
	r := NewHostRegistry("/nonexistent/path/hosts.json")
	if r.IsEnabled() {
		t.Error("registry with missing file should not be enabled")
	}
}

func TestHostRegistryCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	os.WriteFile(path, []byte("not json"), 0600)

	r := NewHostRegistry(path)
	if r.IsEnabled() {
		t.Error("registry with corrupt file should not be enabled")
	}
}

func TestSubtleCompare(t *testing.T) {
	if !subtleCompare("hello", "hello") {
		t.Error("equal strings should match")
	}
	if subtleCompare("hello", "world") {
		t.Error("different strings should not match")
	}
	if subtleCompare("short", "longer-string") {
		t.Error("different length strings should not match")
	}
	if subtleCompare("", "notempty") {
		t.Error("empty vs non-empty should not match")
	}
}

func TestHostRegistryAuthenticateChallenge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")

	registry := NewHostRegistry(path)
	hostSecret, _ := registry.AddHost("myhost", []string{"alice"}, "")

	s := &Server{
		cfg: &Config{
			SharedSecret: "global-secret-long-enough",
		},
		hostRegistry: registry,
	}

	// Test with global secret
	t.Run("global secret authorized", func(t *testing.T) {
		r := &fakeRequest{secret: "global-secret-long-enough"}
		ok, msg := s.authenticateChallenge(r.toHTTPRequest(), "myhost", "alice")
		if !ok {
			t.Errorf("expected authorized, got error: %s", msg)
		}
	})

	// Test global secret but unauthorized user
	t.Run("global secret unauthorized user", func(t *testing.T) {
		r := &fakeRequest{secret: "global-secret-long-enough"}
		ok, msg := s.authenticateChallenge(r.toHTTPRequest(), "myhost", "charlie")
		if ok {
			t.Error("expected unauthorized for charlie on myhost")
		}
		if msg != "user not authorized on this host" {
			t.Errorf("expected user not authorized msg, got: %s", msg)
		}
	})

	// Test per-host secret
	t.Run("per-host secret authorized", func(t *testing.T) {
		r := &fakeRequest{secret: hostSecret}
		ok, msg := s.authenticateChallenge(r.toHTTPRequest(), "myhost", "alice")
		if !ok {
			t.Errorf("expected authorized with host secret, got: %s", msg)
		}
	})

	// Test wrong secret
	t.Run("wrong secret", func(t *testing.T) {
		r := &fakeRequest{secret: "totally-wrong-secret-here"}
		ok, _ := s.authenticateChallenge(r.toHTTPRequest(), "myhost", "alice")
		if ok {
			t.Error("expected unauthorized with wrong secret")
		}
	})
}

// fakeRequest helps create test HTTP requests with X-Shared-Secret header.
type fakeRequest struct {
	secret string
}

func (f *fakeRequest) toHTTPRequest() *http.Request {
	r, _ := http.NewRequest("POST", "/api/challenge", nil)
	if f.secret != "" {
		r.Header.Set("X-Shared-Secret", f.secret)
	}
	return r
}
