package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// testOIDCServer sets up a minimal OIDC provider with a JWKS endpoint
// that serves a test RSA key. Returns the server URL, signing key, and cleanup func.
func testOIDCServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	jwk := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Determine our own URL from the Host header
		scheme := "http"
		issuer := fmt.Sprintf("%s://%s", scheme, r.Host)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 issuer,
			"jwks_uri":              issuer + "/.well-known/jwks.json",
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":        issuer + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, key
}

// signTestJWT creates a signed JWT with the given claims using the test key.
func signTestJWT(t *testing.T, key *rsa.PrivateKey, issuer, clientID, username string, expiry time.Time) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key-1"),
	)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	claims := map[string]interface{}{
		"iss":                issuer,
		"aud":                clientID,
		"sub":                "user-123",
		"preferred_username": username,
		"exp":                expiry.Unix(),
		"iat":                time.Now().Unix(),
	}

	builder := jwt.Signed(signer).Claims(claims)
	token, err := builder.Serialize()
	if err != nil {
		t.Fatalf("serializing JWT: %v", err)
	}
	return token
}

func TestTokenCacheWriteAndCheck(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("token cache tests require root (file ownership checks)")
	}

	oidcServer, key := testOIDCServer(t)
	clientID := "test-client-id"

	cacheDir := t.TempDir()
	tc := NewTokenCache(cacheDir, oidcServer.URL, clientID)

	// Sign a token that expires in 1 hour
	token := signTestJWT(t, key, oidcServer.URL, clientID, "testuser", time.Now().Add(1*time.Hour))

	// Write to cache
	if err := tc.Write("testuser", token, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Verify file exists with correct permissions
	path := filepath.Join(cacheDir, "testuser")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("cache file permissions = %04o, want 0600", perm)
	}

	// Check should succeed and return remaining duration
	remaining, err := tc.Check("testuser")
	if err != nil {
		t.Errorf("Check: %v", err)
	}
	if remaining <= 0 {
		t.Errorf("remaining = %v, want > 0", remaining)
	}
}

func TestTokenCacheExpired(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("token cache tests require root (file ownership checks)")
	}

	oidcServer, key := testOIDCServer(t)
	clientID := "test-client-id"

	cacheDir := t.TempDir()
	tc := NewTokenCache(cacheDir, oidcServer.URL, clientID)

	// Sign a token that expired 1 hour ago
	token := signTestJWT(t, key, oidcServer.URL, clientID, "testuser", time.Now().Add(-1*time.Hour))

	if err := tc.Write("testuser", token, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Check should fail (expired)
	if _, err := tc.Check("testuser"); err == nil {
		t.Error("Check should fail for expired token")
	}
}

func TestTokenCacheMissing(t *testing.T) {
	cacheDir := t.TempDir()
	tc := NewTokenCache(cacheDir, "http://localhost", "client-id")

	if _, err := tc.Check("nonexistent"); err == nil {
		t.Error("Check should fail for missing cache file")
	}
}

func TestTokenCacheInvalidJSON(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("token cache tests require root (file ownership checks)")
	}

	cacheDir := t.TempDir()
	tc := NewTokenCache(cacheDir, "http://localhost", "client-id")

	// Write garbage to cache file
	path := filepath.Join(cacheDir, "testuser")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	if _, err := tc.Check("testuser"); err == nil {
		t.Error("Check should fail for invalid JSON")
	}
}

func TestTokenCacheWrongUsername(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("token cache tests require root (file ownership checks)")
	}

	oidcServer, key := testOIDCServer(t)
	clientID := "test-client-id"

	cacheDir := t.TempDir()
	tc := NewTokenCache(cacheDir, oidcServer.URL, clientID)

	// Sign a token for "alice" but cache it under "bob"
	token := signTestJWT(t, key, oidcServer.URL, clientID, "alice", time.Now().Add(1*time.Hour))

	if err := tc.Write("bob", token, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Check as "bob" should fail — token's preferred_username is "alice"
	if _, err := tc.Check("bob"); err == nil {
		t.Error("Check should fail when token username doesn't match")
	}
}

func TestTokenCacheWrongAudience(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("token cache tests require root (file ownership checks)")
	}

	oidcServer, key := testOIDCServer(t)

	cacheDir := t.TempDir()
	// Cache expects "correct-client-id" but token has "wrong-client-id"
	tc := NewTokenCache(cacheDir, oidcServer.URL, "correct-client-id")

	token := signTestJWT(t, key, oidcServer.URL, "wrong-client-id", "testuser", time.Now().Add(1*time.Hour))

	if err := tc.Write("testuser", token, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Check should fail — audience mismatch
	if _, err := tc.Check("testuser"); err == nil {
		t.Error("Check should fail for wrong audience")
	}
}

func TestTokenCacheDirectoryCreation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("token cache tests require root (file ownership checks)")
	}

	oidcServer, key := testOIDCServer(t)
	clientID := "test-client-id"

	base := t.TempDir()
	cacheDir := filepath.Join(base, "nested", "cache")
	tc := NewTokenCache(cacheDir, oidcServer.URL, clientID)

	token := signTestJWT(t, key, oidcServer.URL, clientID, "testuser", time.Now().Add(1*time.Hour))

	if err := tc.Write("testuser", token, 0); err != nil {
		t.Fatalf("Write should create nested directories: %v", err)
	}

	// Verify directory was created
	info, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatalf("stat cache dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("cache dir should be a directory")
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("cache dir permissions = %04o, want 0700", perm)
	}
}

func TestTokenCacheWriteMalformedJWT(t *testing.T) {
	cacheDir := t.TempDir()
	tc := NewTokenCache(cacheDir, "http://localhost", "client-id")

	if err := tc.Write("testuser", "not-a-jwt", 0); err == nil {
		t.Error("Write should fail for malformed JWT")
	}
}

func TestTokenCacheWriteNoExpClaim(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("token cache tests require root (file ownership checks)")
	}

	oidcServer, key := testOIDCServer(t)
	clientID := "test-client-id"

	// Create a JWT without exp claim
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key-1"),
	)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	claims := map[string]interface{}{
		"iss":                oidcServer.URL,
		"aud":                clientID,
		"sub":                "user-123",
		"preferred_username": "testuser",
		"iat":                time.Now().Unix(),
		// no "exp"
	}
	builder := jwt.Signed(signer).Claims(claims)
	token, err := builder.Serialize()
	if err != nil {
		t.Fatalf("serializing JWT: %v", err)
	}

	cacheDir := t.TempDir()
	tc := NewTokenCache(cacheDir, oidcServer.URL, clientID)

	if err := tc.Write("testuser", token, 0); err == nil {
		t.Error("Write should fail for JWT without exp claim")
	}
}

func TestTokenCacheIssuerUnreachable(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("token cache tests require root (file ownership checks)")
	}

	// Use an unreachable issuer — Check should fail gracefully
	cacheDir := t.TempDir()
	tc := NewTokenCache(cacheDir, "http://127.0.0.1:1", "client-id")

	// Write a fake cache file manually (bypass Write since we need an unreachable issuer)
	cached := cachedToken{
		IDToken:   "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.fake",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	data, _ := json.Marshal(cached)
	path := filepath.Join(cacheDir, "testuser")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Check should fail (can't reach issuer for JWKS) but not panic
	if _, err := tc.Check("testuser"); err == nil {
		t.Error("Check should fail when issuer is unreachable")
	}
}

// TestPollResponseIncludesIDToken verifies the server returns id_token
// in the poll response after approval.
func TestPollResponseIncludesIDToken(t *testing.T) {
	s, ts := setupTestServer(t)
	_ = s

	// Create a challenge
	body := `{"username":"jordan"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	defer resp.Body.Close()

	var cr challengeResponse
	json.NewDecoder(resp.Body).Decode(&cr)

	// Manually approve and set an id_token
	s.store.Approve(cr.ChallengeID, "jordan")
	s.store.SetIDToken(cr.ChallengeID, "test-id-token-value")

	// Poll the challenge
	req2, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+cr.ChallengeID, nil)
	req2.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("poll challenge: %v", err)
	}
	defer resp2.Body.Close()

	var pr map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&pr)

	if pr["id_token"] != "test-id-token-value" {
		t.Errorf("poll response id_token = %v, want %q", pr["id_token"], "test-id-token-value")
	}
}

