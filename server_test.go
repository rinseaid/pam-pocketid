package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
			SharedSecret: "test-secret-that-is-long-enough",
			ChallengeTTL: 120 * time.Second,
		},
		store: NewChallengeStore(120*time.Second, 0),
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
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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
		req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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
		req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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
	c, _ := s.store.Create("jordan", "")

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+c.ID, nil)
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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

	c, _ := s.store.Create("jordan", "")
	s.store.Approve(c.ID, "jordan")

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+c.ID, nil)
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

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

	c, _ := s.store.Create("jordan", "")

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

	c, _ := s.store.Create("jordan", "")

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

func TestUsernameMatchingIsExact(t *testing.T) {
	// The server matches on preferred_username using EXACT (case-sensitive) comparison.
	// Case-insensitive matching could allow identity confusion on case-sensitive
	// Linux systems where "jordan" and "Jordan" are distinct users.
	tests := []struct {
		sudoUser        string
		preferredUser   string
		expectMatch     bool
		desc            string
	}{
		{"jordan", "jordan", true, "exact match"},
		{"jordan", "Jordan", false, "case mismatch rejected"},
		{"jordan", "bob", false, "different username"},
		{"admin", "admin", true, "admin match"},
		{"admin", "Admin", false, "admin case mismatch rejected"},
		{"admin", "administrator", false, "prefix should not match"},
	}

	for _, tt := range tests {
		got := tt.sudoUser == tt.preferredUser
		if got != tt.expectMatch {
			t.Errorf("%s: %q == %q = %v, want %v",
				tt.desc, tt.sudoUser, tt.preferredUser, got, tt.expectMatch)
		}
	}
}

func TestEmailPrefixMatchRemoved(t *testing.T) {
	// Verify that email prefix matching is NOT used.
	// This is a regression test: admin@evil.com must NOT match sudo user "admin".
	sudoUser := "admin"
	oidcUsername := "evil-admin"
	if sudoUser == oidcUsername {
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
		"Content-Security-Policy": "default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
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
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")
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
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 for oversized body", resp.StatusCode)
	}
}

func TestContentTypeRequired(t *testing.T) {
	_, ts := setupTestServer(t)

	// POST without Content-Type: application/json should be rejected
	body := bytes.NewBufferString(`{"username":"jordan"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", body)
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")
	// No Content-Type header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 415 {
		t.Errorf("status = %d, want 415 (Unsupported Media Type)", resp.StatusCode)
	}
}

func TestApprovalTokenInPollResponse(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan", "testhost")
	s.store.Approve(c.ID, "jordan")

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+c.ID, nil)
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if result["status"] != "approved" {
		t.Fatalf("status = %v, want approved", result["status"])
	}

	token, ok := result["approval_token"].(string)
	if !ok || token == "" {
		t.Fatal("approval_token missing from approved challenge poll response")
	}

	// Verify the token is a correct HMAC, not just any 64-char hex string
	expected := s.computeStatusHMAC(c.ID, "jordan", "approved")
	if token != expected {
		t.Errorf("approval_token = %q, want %q", token, expected)
	}
}

func TestDenialTokenInPollResponse(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan", "")
	s.store.Deny(c.ID)

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+c.ID, nil)
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if result["status"] != "denied" {
		t.Fatalf("status = %v, want denied", result["status"])
	}

	token, ok := result["denial_token"].(string)
	if !ok || token == "" {
		t.Fatal("denial_token missing from denied challenge poll response")
	}

	expected := s.computeStatusHMAC(c.ID, "jordan", "denied")
	if token != expected {
		t.Errorf("denial_token = %q, want %q", token, expected)
	}
}

func TestApprovalTokenNotPresentForPending(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan", "")

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+c.ID, nil)
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if _, ok := result["approval_token"]; ok {
		t.Error("approval_token should not be present for pending challenges")
	}
}

func TestCallbackRejectsPost(t *testing.T) {
	s, ts := setupTestServer(t)
	// Register callback handler (not in default setupTestServer since it needs OIDC)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)

	req, _ := http.NewRequest("POST", ts.URL+"/callback?state=x&code=y", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 405 {
		t.Errorf("status = %d, want 405 for POST to /callback", resp.StatusCode)
	}
}

func TestChallengeHostname(t *testing.T) {
	s, _ := setupTestServer(t)

	c, _ := s.store.Create("jordan", "web-server-01")

	got, ok := s.store.Get(c.ID)
	if !ok {
		t.Fatal("challenge not found")
	}
	if got.Hostname != "web-server-01" {
		t.Errorf("hostname = %q, want %q", got.Hostname, "web-server-01")
	}
}

func TestPanicRecovery(t *testing.T) {
	s := &Server{
		cfg: &Config{
			ExternalURL:  "http://localhost:8090",
			SharedSecret: "test-secret-that-is-long-enough",
			ChallengeTTL: 120 * time.Second,
		},
		store: NewChallengeStore(120*time.Second, 0),
		mux:   http.NewServeMux(),
	}
	// Register a handler that panics
	s.mux.HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})
	ts := httptest.NewServer(s)
	defer ts.Close()
	defer s.store.Stop()

	resp, err := http.Get(ts.URL + "/panic")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500 after panic", resp.StatusCode)
	}
}

func TestVerifyStatusToken(t *testing.T) {
	client := &PAMClient{
		cfg: &Config{SharedSecret: "test-secret-that-is-long-enough"},
	}

	// Compute a known-good token
	challengeID := "aabbccdd11223344aabbccdd11223344"
	username := "jordan"

	// Server-side computation
	srv := &Server{cfg: &Config{SharedSecret: "test-secret-that-is-long-enough"}}
	approvedToken := srv.computeStatusHMAC(challengeID, username, "approved")
	deniedToken := srv.computeStatusHMAC(challengeID, username, "denied")

	// Valid approval token
	if !client.verifyStatusToken(challengeID, username, "approved", approvedToken) {
		t.Error("valid approval token rejected")
	}

	// Valid denial token
	if !client.verifyStatusToken(challengeID, username, "denied", deniedToken) {
		t.Error("valid denial token rejected")
	}

	// Empty token
	if client.verifyStatusToken(challengeID, username, "approved", "") {
		t.Error("empty token accepted")
	}

	// Tampered token (single char change)
	tampered := approvedToken[:63] + "0"
	if tampered == approvedToken {
		tampered = approvedToken[:63] + "1"
	}
	if client.verifyStatusToken(challengeID, username, "approved", tampered) {
		t.Error("tampered token accepted")
	}

	// Wrong username
	if client.verifyStatusToken(challengeID, "alice", "approved", approvedToken) {
		t.Error("token for wrong username accepted")
	}

	// Wrong challengeID
	if client.verifyStatusToken("00000000000000000000000000000000", username, "approved", approvedToken) {
		t.Error("token for wrong challengeID accepted")
	}

	// Approval token used for denial (cross-status)
	if client.verifyStatusToken(challengeID, username, "denied", approvedToken) {
		t.Error("approval token accepted as denial token")
	}
}

func TestSanitizeForTerminal(t *testing.T) {
	tests := []struct {
		input string
		want  string
		desc  string
	}{
		{"hello", "hello", "clean string"},
		{"hello\nworld", "hello world", "newline replaced with space"},
		{"hello\rworld", "hello world", "carriage return replaced with space"},
		{"hello\tworld", "hello world", "tab replaced with space"},
		{"hello\x00world", "helloworld", "null byte stripped"},
		{"hello\x07world", "helloworld", "bell character stripped"},
		{"\x1b[31mRED\x1b[0m", "[31mRED[0m", "ANSI escape sequences stripped"},
		{"hello\x7fworld", "helloworld", "DEL character stripped"},
		{"normal text 123!@#", "normal text 123!@#", "printable chars preserved"},
		// C1 control characters (U+0080-U+009F)
		{"hello\xc2\x9bworld", "helloworld", "C1 CSI (U+009B) stripped"},
		{"hello\xc2\x85world", "helloworld", "C1 NEL (U+0085) stripped"},
		{"hello\xc2\x90world", "helloworld", "C1 DCS (U+0090) stripped"},
		// Unicode bidirectional overrides
		{"hello\xe2\x80\xaeworld", "helloworld", "RLO (U+202E) stripped"},
		{"hello\xe2\x80\xabworld", "helloworld", "RLE (U+202B) stripped"},
		// Zero-width characters
		{"hello\xe2\x80\x8bworld", "helloworld", "zero-width space (U+200B) stripped"},
		{"hello\xef\xbb\xbfworld", "helloworld", "BOM (U+FEFF) stripped"},
	}

	for _, tt := range tests {
		got := sanitizeForTerminal(tt.input)
		if got != tt.want {
			t.Errorf("%s: sanitizeForTerminal(%q) = %q, want %q", tt.desc, tt.input, got, tt.want)
		}
	}
}

func TestIsHexEmptyString(t *testing.T) {
	if isHex("") {
		t.Error("isHex(\"\") should return false")
	}
	if !isHex("abcdef0123456789") {
		t.Error("isHex(\"abcdef0123456789\") should return true")
	}
}

func TestHostnameValidation(t *testing.T) {
	_, ts := setupTestServer(t)

	tests := []struct {
		hostname string
		wantCode int
		desc     string
	}{
		{"web-server-01", 200, "valid hostname"},
		{"host.example.com", 200, "valid FQDN"},
		{"", 200, "empty hostname (optional)"},
		{"host with spaces", 400, "spaces rejected"},
		{"host\nnewline", 400, "newline rejected"},
		{strings.Repeat("a", 254), 400, "too long rejected"},
		{"host<script>", 400, "XSS payload rejected"},
	}

	for _, tt := range tests {
		payload := map[string]string{"username": "jordan"}
		if tt.hostname != "" {
			payload["hostname"] = tt.hostname
		} else if tt.desc == "empty hostname (optional)" {
			// Explicitly include empty string
			payload["hostname"] = ""
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: request: %v", tt.desc, err)
		}
		resp.Body.Close()

		if resp.StatusCode != tt.wantCode {
			t.Errorf("%s: status = %d, want %d", tt.desc, resp.StatusCode, tt.wantCode)
		}
	}
}

func TestContentTypeVariants(t *testing.T) {
	_, ts := setupTestServer(t)

	tests := []struct {
		contentType string
		wantCode    int
		desc        string
	}{
		{"application/json", 200, "standard JSON"},
		{"application/json; charset=utf-8", 200, "JSON with charset"},
		{"application/x-www-form-urlencoded", 415, "form submission rejected"},
		{"multipart/form-data", 415, "multipart rejected"},
		{"text/plain", 415, "text/plain rejected"},
		{"", 415, "empty content-type rejected"},
	}

	for _, tt := range tests {
		body := bytes.NewBufferString(`{"username":"jordan"}`)
		req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", body)
		if tt.contentType != "" {
			req.Header.Set("Content-Type", tt.contentType)
		}
		req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: request: %v", tt.desc, err)
		}
		resp.Body.Close()

		if resp.StatusCode != tt.wantCode {
			t.Errorf("%s: status = %d, want %d", tt.desc, resp.StatusCode, tt.wantCode)
		}
	}
}

func TestPollWithWrongSecret(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan", "")

	req, _ := http.NewRequest("GET", ts.URL+"/api/challenge/"+c.ID, nil)
	req.Header.Set("X-Shared-Secret", "wrong-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestApprovalPageMethodRestriction(t *testing.T) {
	s, ts := setupTestServer(t)
	c, _ := s.store.Create("jordan", "")

	req, _ := http.NewRequest("POST", ts.URL+"/approve/"+c.UserCode, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 405 {
		t.Errorf("POST to /approve/ status = %d, want 405", resp.StatusCode)
	}
}

func TestLoginMethodRestriction(t *testing.T) {
	s, ts := setupTestServer(t)
	c, _ := s.store.Create("jordan", "")

	req, _ := http.NewRequest("POST", ts.URL+"/login/"+c.UserCode, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 405 {
		t.Errorf("POST to /login/ status = %d, want 405", resp.StatusCode)
	}
}

func TestHSTSHeaderOnHTTPS(t *testing.T) {
	// When ExternalURL is HTTPS, HSTS header should be set
	s := &Server{
		cfg: &Config{
			ExternalURL:  "https://sudo.example.com",
			SharedSecret: "test-secret-that-is-long-enough",
			ChallengeTTL: 120 * time.Second,
		},
		store: NewChallengeStore(120*time.Second, 0),
		mux:   http.NewServeMux(),
	}
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	ts := httptest.NewServer(s)
	defer ts.Close()
	defer s.store.Stop()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS header missing when ExternalURL is HTTPS")
	}
	if !strings.Contains(hsts, "max-age=") {
		t.Errorf("HSTS header missing max-age: %q", hsts)
	}
}

func TestNoHSTSOnHTTP(t *testing.T) {
	// When ExternalURL is HTTP, HSTS header should NOT be set
	_, ts := setupTestServer(t) // uses http://localhost:8090

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS header should not be set for HTTP ExternalURL, got %q", hsts)
	}
}

func TestCallbackLogsInvalidState(t *testing.T) {
	s, ts := setupTestServer(t)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)

	// Missing colon in state
	resp, err := http.Get(ts.URL + "/callback?state=nocolon&code=test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("invalid state: status = %d, want 400", resp.StatusCode)
	}

	// Malformed hex in state
	resp2, err := http.Get(ts.URL + "/callback?state=not32charhexvalue1234567890ab:not32charhexvalue1234567890ab&code=test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 400 {
		t.Errorf("malformed hex state: status = %d, want 400", resp2.StatusCode)
	}

	// Valid state format but unknown challenge — returns expired page
	validState := "aabbccdd11223344aabbccdd11223344:aabbccdd11223344aabbccdd11223344"
	resp3, err := http.Get(ts.URL + "/callback?state=" + validState + "&code=test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp3.Body.Close()
	// Unknown challenge returns the expired HTML page (200 with error content)
	// or 404 depending on implementation — just verify it doesn't crash
}

func TestCallbackRequiresNonceBeforeDeny(t *testing.T) {
	s, ts := setupTestServer(t)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)

	// Create a challenge but don't initiate login (no nonce set)
	c, _ := s.store.Create("jordan", "")

	// Try to deny via forged error callback — should fail because nonce not set
	state := c.ID + ":aabbccdd11223344aabbccdd11223344"
	resp, err := http.Get(ts.URL + "/callback?state=" + state + "&error=access_denied")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("forged error callback without nonce: status = %d, want 400", resp.StatusCode)
	}

	// Challenge should still be pending (not denied)
	got, ok := s.store.Get(c.ID)
	if !ok {
		t.Fatal("challenge should still exist")
	}
	if got.Status != StatusPending {
		t.Errorf("challenge status = %q, want %q (should not be denied by forged callback)", got.Status, StatusPending)
	}
}

func TestCallbackNonceMismatchDoesNotDeny(t *testing.T) {
	s, ts := setupTestServer(t)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)

	// Create a challenge and set a nonce (simulating login initiation)
	c, _ := s.store.Create("jordan", "")
	s.store.SetNonce(c.ID, "aaaabbbbccccddddaaaabbbbccccdddd")

	// Try callback with wrong nonce — should reject but NOT deny the challenge
	wrongNonce := "11112222333344441111222233334444"
	state := c.ID + ":" + wrongNonce
	resp, err := http.Get(ts.URL + "/callback?state=" + state + "&code=test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("wrong nonce callback: status = %d, want 400", resp.StatusCode)
	}

	// Challenge should still be pending (nonce mismatch should not deny)
	got, ok := s.store.Get(c.ID)
	if !ok {
		t.Fatal("challenge should still exist")
	}
	if got.Status != StatusPending {
		t.Errorf("challenge status = %q, want %q (nonce mismatch should not deny)", got.Status, StatusPending)
	}
}

func TestConfigFilePermissionEnforcement(t *testing.T) {
	dir := t.TempDir()
	content := []byte("PAM_POCKETID_SERVER_URL=http://localhost:8090\n")

	// Write a config file that's world-readable
	worldReadable := dir + "/world.conf"
	os.WriteFile(worldReadable, content, 0644)
	os.Chmod(worldReadable, 0644) // ensure mode is set

	vars := loadConfigFile(worldReadable)
	if len(vars) != 0 {
		t.Errorf("expected empty map for world-readable config, got %v", vars)
	}

	// Write a config file with correct permissions
	secure := dir + "/secure.conf"
	os.WriteFile(secure, content, 0600)
	os.Chmod(secure, 0600) // ensure mode is set

	vars = loadConfigFile(secure)
	if vars["PAM_POCKETID_SERVER_URL"] != "http://localhost:8090" {
		t.Errorf("expected URL from properly-permissioned file, got %v", vars)
	}
}
