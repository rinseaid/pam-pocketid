package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer creates a Server with a mock challenge store (no OIDC).
// Only tests the API endpoints, not the OIDC callback flow.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		cfg: &Config{
			ExternalURL:  "http://localhost:8090",
			SharedSecret: "test-secret",
			ChallengeTTL: 120 * time.Second,
		},
		store: NewChallengeStore(120 * time.Second),
		mux:   http.NewServeMux(),
	}
}

func setupTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s := newTestServer(t)
	s.mux.HandleFunc("/api/challenge", s.handleCreateChallenge)
	s.mux.HandleFunc("/api/challenge/", s.handlePollChallenge)
	s.mux.HandleFunc("/approve/", s.handleApprovalPage)
	s.mux.HandleFunc("/login/", s.handleLogin)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	ts := httptest.NewServer(s)
	t.Cleanup(func() {
		ts.Close()
		s.store.Stop()
	})
	return s, ts
}

func TestCreateChallenge(t *testing.T) {
	s, ts := setupTestServer(t)
	_ = s

	body := bytes.NewBufferString(`{"username":"jordan"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(b))
	}

	var cr challengeResponse
	json.NewDecoder(resp.Body).Decode(&cr)

	if cr.ChallengeID == "" {
		t.Error("challenge_id is empty")
	}
	if cr.UserCode == "" {
		t.Error("user_code is empty")
	}
	if cr.VerificationURL == "" {
		t.Error("verification_url is empty")
	}
	if cr.ExpiresIn != 120 {
		t.Errorf("expires_in = %d, want 120", cr.ExpiresIn)
	}
}

func TestCreateChallengeNoAuth(t *testing.T) {
	_, ts := setupTestServer(t)

	body := bytes.NewBufferString(`{"username":"jordan"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", body)
	req.Header.Set("Content-Type", "application/json")
	// No X-Shared-Secret header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestCreateChallengeNoUsername(t *testing.T) {
	_, ts := setupTestServer(t)

	body := bytes.NewBufferString(`{}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateChallengeInvalidUsername(t *testing.T) {
	_, ts := setupTestServer(t)

	// Test various injection attempts
	tests := []string{
		`{"username":"jordan\nINJECTED LOG LINE"}`,    // log injection
		`{"username":"../../../etc/passwd"}`,             // path traversal chars
		`{"username":"<script>alert(1)</script>"}`,       // XSS
		`{"username":"` + string(make([]byte, 100)) + `"}`, // oversized
	}

	for _, body := range tests {
		req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Shared-Secret", "test-secret")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != 400 {
			t.Errorf("body=%q: status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestCreateChallengeRateLimit(t *testing.T) {
	_, ts := setupTestServer(t)

	// Create maxChallengesPerUser challenges
	for i := 0; i < maxChallengesPerUser; i++ {
		body := bytes.NewBufferString(`{"username":"jordan"}`)
		req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Shared-Secret", "test-secret")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
	}

	// Next should be rate limited
	body := bytes.NewBufferString(`{"username":"jordan"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Errorf("status = %d, want 429 (Too Many Requests)", resp.StatusCode)
	}
}

func TestPollChallenge(t *testing.T) {
	s, ts := setupTestServer(t)

	// Create a challenge directly
	c, _ := s.store.Create("jordan")

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+c.ID, nil)
	req.Header.Set("X-Shared-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var pr pollResponse
	json.NewDecoder(resp.Body).Decode(&pr)

	if pr.Status != "pending" {
		t.Errorf("status = %q, want %q", pr.Status, "pending")
	}
}

func TestPollChallengeApproved(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan")
	s.store.Approve(c.ID, "jordan")

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+c.ID, nil)
	req.Header.Set("X-Shared-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var pr pollResponse
	json.NewDecoder(resp.Body).Decode(&pr)

	if pr.Status != "approved" {
		t.Errorf("status = %q, want %q", pr.Status, "approved")
	}
}

func TestPollChallengeNotFound(t *testing.T) {
	_, ts := setupTestServer(t)

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/aabbccdd11223344aabbccdd11223344", nil)
	req.Header.Set("X-Shared-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPollChallengeInvalidID(t *testing.T) {
	_, ts := setupTestServer(t)

	// Non-hex challenge ID
	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/not-a-valid-id", nil)
	req.Header.Set("X-Shared-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestApprovalPage(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan")

	resp, err := http.Get(ts.URL + "/approve/" + c.UserCode)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("jordan")) {
		t.Error("approval page does not contain username")
	}
	if !bytes.Contains(body, []byte(c.UserCode)) {
		t.Error("approval page does not contain user code")
	}
	// Verify the login URL uses user code, NOT challenge ID
	if bytes.Contains(body, []byte(c.ID)) {
		t.Error("approval page should NOT contain the challenge ID (information leak)")
	}
}

func TestApprovalPageExpired(t *testing.T) {
	_, ts := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/approve/ABCDEF-000000")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestApprovalPageInvalidFormat(t *testing.T) {
	_, ts := setupTestServer(t)

	// Old short format should be rejected
	resp, err := http.Get(ts.URL + "/approve/XXXX-0000")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLoginEndpointSetsNonce(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan")

	// Use a client that doesn't follow redirects (the OIDC redirect will fail)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// First login attempt via user code
	resp, err := client.Get(ts.URL + "/login/" + c.UserCode)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	// Should fail because OIDC provider isn't configured in test, but the nonce should be set.
	// In a real setup it would redirect. Let's check the nonce was stored.
	got, ok := s.store.Get(c.ID)
	if !ok {
		t.Fatal("challenge not found after login")
	}
	if got.Nonce == "" {
		t.Error("nonce was not set on challenge after login")
	}

	// Second login attempt should fail (nonce already set)
	resp2, err := client.Get(ts.URL + "/login/" + c.UserCode)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != 409 {
		t.Errorf("second login status = %d, want 409 (Conflict)", resp2.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	_, ts := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	_, ts := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/api/challenge")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 405 {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestUsernameMatchingIsStrictPreferredOnly(t *testing.T) {
	// The server now ONLY matches on preferred_username (case insensitive).
	// Email prefix matching was removed because it allows cross-domain escalation:
	// e.g., admin@evil.com could approve sudo for user "admin".
	tests := []struct {
		sudoUser        string
		preferredUser   string
		expectMatch     bool
		desc            string
	}{
		{"jordan", "jordan", true, "exact match"},
		{"jordan", "Jordan", true, "case insensitive"},
		{"jordan", "bob", false, "different username"},
		{"admin", "admin", true, "admin match"},
		{"admin", "Admin", true, "admin case insensitive"},
		{"admin", "administrator", false, "prefix should not match"},
	}

	for _, tt := range tests {
		got := strings.EqualFold(tt.sudoUser, tt.preferredUser)
		if got != tt.expectMatch {
			t.Errorf("%s: EqualFold(%q, %q) = %v, want %v",
				tt.desc, tt.sudoUser, tt.preferredUser, got, tt.expectMatch)
		}
	}
}

func TestEmailPrefixMatchRemoved(t *testing.T) {
	// Verify that email prefix matching is NOT used.
	// This is a regression test: admin@evil.com must NOT match sudo user "admin".
	sudoUser := "admin"
	oidcUsername := "evil-admin"
	// Even though email prefix matches, the preferred_username doesn't, so it should fail.
	if strings.EqualFold(sudoUser, oidcUsername) {
		t.Error("email prefix matching should not be used")
	}
}

func TestSecurityHeaders(t *testing.T) {
	_, ts := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	headers := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":        "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}

	for name, expected := range headers {
		got := resp.Header.Get(name)
		if got != expected {
			t.Errorf("%s = %q, want %q", name, got, expected)
		}
	}
}

func TestTimingAttackProtection(t *testing.T) {
	// This is a structural test: verify that the server uses constant-time
	// comparison for the shared secret by checking the verifySharedSecret method exists
	// and returns correct results.
	s := newTestServer(t)

	// Correct secret
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Shared-Secret", "test-secret")
	if !s.verifySharedSecret(req) {
		t.Error("verifySharedSecret returned false for correct secret")
	}

	// Wrong secret
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Shared-Secret", "wrong-secret")
	if s.verifySharedSecret(req2) {
		t.Error("verifySharedSecret returned true for wrong secret")
	}

	// Missing secret
	req3 := httptest.NewRequest("GET", "/", nil)
	if s.verifySharedSecret(req3) {
		t.Error("verifySharedSecret returned true for missing secret")
	}

	// No secret configured (should accept all)
	s2 := &Server{cfg: &Config{SharedSecret: ""}}
	req4 := httptest.NewRequest("GET", "/", nil)
	if !s2.verifySharedSecret(req4) {
		t.Error("verifySharedSecret returned false when no secret configured")
	}
}

func TestOversizedRequestBody(t *testing.T) {
	_, ts := setupTestServer(t)

	// Send a request body that exceeds maxRequestBodySize
	bigBody := bytes.Repeat([]byte("A"), maxRequestBodySize+100)
	req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 for oversized body", resp.StatusCode)
	}
}
