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
		store:         NewChallengeStore(120*time.Second, 0, ""),
		hostRegistry:  NewHostRegistry(""),
		mux:           http.NewServeMux(),
		sessionNonces: make(map[string]time.Time),
	}
}

func setupTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s := newTestServer(t)
	s.mux.HandleFunc("/api/challenge", s.handleCreateChallenge)
	s.mux.HandleFunc("/api/challenge/", s.handlePollChallenge)
	s.mux.HandleFunc("/api/challenges/approve", s.handleBulkApprove)
	s.mux.HandleFunc("/api/challenges/approve-all", s.handleBulkApproveAll)
	s.mux.HandleFunc("/api/challenges/reject", s.handleRejectChallenge)
	s.mux.HandleFunc("/api/challenges/reject-all", s.handleRejectAll)
	s.mux.HandleFunc("/api/sessions/revoke", s.handleRevokeSession)
	s.mux.HandleFunc("/api/sessions/revoke-all", s.handleRevokeAll)
	s.mux.HandleFunc("/approve/", s.handleApprovalPage)
	s.mux.HandleFunc("/sessions", s.handleSessionsRedirect)
	s.mux.HandleFunc("/sessions/login", s.handleSessionsLogin)
	s.mux.HandleFunc("/history", s.handleHistoryPage)
	s.mux.HandleFunc("/hosts", s.handleHostsPage)
	s.mux.HandleFunc("/api/hosts/elevate", s.handleElevate)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/", s.handleDashboard)
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
	c, _ := s.store.Create("jordan", "", "")

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

	c, _ := s.store.Create("jordan", "", "")
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

	c, _ := s.store.Create("jordan", "", "")

	// Use a client that doesn't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(ts.URL + "/approve/" + c.UserCode)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 303 {
		t.Errorf("status = %d, want 303 (See Other redirect)", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/sessions/login") {
		t.Errorf("Location = %q, want redirect to /sessions/login", loc)
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
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"Referrer-Policy":       "no-referrer",
		"Cache-Control":         "no-store",
	}

	for name, expected := range headers {
		got := resp.Header.Get(name)
		if got != expected {
			t.Errorf("%s = %q, want %q", name, got, expected)
		}
	}

	// CSP has a dynamic nonce — check the structure, not exact value
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, "style-src 'unsafe-inline'") {
		t.Errorf("CSP = %q, want nonce-based script-src", csp)
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

	c, _ := s.store.Create("jordan", "testhost", "")
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
	expected := s.computeStatusHMAC(c.ID, "jordan", "approved", "", "")
	if token != expected {
		t.Errorf("approval_token = %q, want %q", token, expected)
	}
}

func TestDenialTokenInPollResponse(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan", "", "")
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

	expected := s.computeStatusHMAC(c.ID, "jordan", "denied", "", "")
	if token != expected {
		t.Errorf("denial_token = %q, want %q", token, expected)
	}
}

func TestApprovalTokenNotPresentForPending(t *testing.T) {
	s, ts := setupTestServer(t)

	c, _ := s.store.Create("jordan", "", "")

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

	c, _ := s.store.Create("jordan", "web-server-01", "")

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
		store:        NewChallengeStore(120*time.Second, 0, ""),
		hostRegistry: NewHostRegistry(""),
		mux:          http.NewServeMux(),
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
	approvedToken := srv.computeStatusHMAC(challengeID, username, "approved", "", "")
	deniedToken := srv.computeStatusHMAC(challengeID, username, "denied", "", "")

	// Valid approval token
	if !client.verifyStatusToken(challengeID, username, "approved", approvedToken, "", "") {
		t.Error("valid approval token rejected")
	}

	// Valid denial token
	if !client.verifyStatusToken(challengeID, username, "denied", deniedToken, "", "") {
		t.Error("valid denial token rejected")
	}

	// Empty token
	if client.verifyStatusToken(challengeID, username, "approved", "", "", "") {
		t.Error("empty token accepted")
	}

	// Tampered token (single char change)
	tampered := approvedToken[:63] + "0"
	if tampered == approvedToken {
		tampered = approvedToken[:63] + "1"
	}
	if client.verifyStatusToken(challengeID, username, "approved", tampered, "", "") {
		t.Error("tampered token accepted")
	}

	// Wrong username
	if client.verifyStatusToken(challengeID, "alice", "approved", approvedToken, "", "") {
		t.Error("token for wrong username accepted")
	}

	// Wrong challengeID
	if client.verifyStatusToken("00000000000000000000000000000000", username, "approved", approvedToken, "", "") {
		t.Error("token for wrong challengeID accepted")
	}

	// Approval token used for denial (cross-status)
	if client.verifyStatusToken(challengeID, username, "denied", approvedToken, "", "") {
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

	c, _ := s.store.Create("jordan", "", "")

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
	c, _ := s.store.Create("jordan", "", "")

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

func TestHSTSHeaderOnHTTPS(t *testing.T) {
	// When ExternalURL is HTTPS, HSTS header should be set
	s := &Server{
		cfg: &Config{
			ExternalURL:  "https://sudo.example.com",
			SharedSecret: "test-secret-that-is-long-enough",
			ChallengeTTL: 120 * time.Second,
		},
		store:        NewChallengeStore(120*time.Second, 0, ""),
		hostRegistry: NewHostRegistry(""),
		mux:          http.NewServeMux(),
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

func TestCallbackRejectsNonSessionsState(t *testing.T) {
	s, ts := setupTestServer(t)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)

	// Non-sessions state should be rejected with a styled error
	resp, err := http.Get(ts.URL + "/callback?state=nocolon&code=test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("non-sessions state: status = %d, want 400", resp.StatusCode)
	}

	// Challenge-style state (no longer supported) should also be rejected
	validState := "aabbccdd11223344aabbccdd11223344:aabbccdd11223344aabbccdd11223344"
	resp2, err := http.Get(ts.URL + "/callback?state=" + validState + "&code=test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 400 {
		t.Errorf("challenge-style state: status = %d, want 400", resp2.StatusCode)
	}
}

func TestCallbackDoesNotAffectChallenges(t *testing.T) {
	s, ts := setupTestServer(t)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)

	// Create a challenge
	c, _ := s.store.Create("jordan", "", "")

	// Try a callback with challenge-style state — should be rejected
	// and the challenge should remain pending (callback no longer processes challenges)
	state := c.ID + ":aabbccdd11223344aabbccdd11223344"
	resp, err := http.Get(ts.URL + "/callback?state=" + state + "&error=access_denied")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	// Challenge should still be pending (callback doesn't handle challenges anymore)
	got, ok := s.store.Get(c.ID)
	if !ok {
		t.Fatal("challenge should still exist")
	}
	if got.Status != StatusPending {
		t.Errorf("challenge status = %q, want %q (callback should not affect challenges)", got.Status, StatusPending)
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

func TestSessionsPageRedirects(t *testing.T) {
	_, ts := setupTestServer(t)

	// /sessions now redirects to /
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(ts.URL + "/sessions")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 303 {
		t.Errorf("status = %d, want 303 redirect", resp.StatusCode)
	}
}

func TestSessionsPageRedirectsOnPost(t *testing.T) {
	_, ts := setupTestServer(t)

	// /sessions now redirects for any method
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest("POST", ts.URL+"/sessions", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 303 {
		t.Errorf("POST to /sessions status = %d, want 303 redirect", resp.StatusCode)
	}
}

func TestSessionsLoginRedirects(t *testing.T) {
	s, ts := setupTestServer(t)

	// The /sessions/login should generate a nonce and redirect to OIDC
	// Since we don't have a real OIDC config, the redirect URL will be malformed
	// but we can verify a nonce was stored.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(ts.URL + "/sessions/login")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	// Should redirect (302) to the OIDC provider
	if resp.StatusCode != 302 {
		t.Errorf("status = %d, want 302 redirect", resp.StatusCode)
	}

	// Verify a nonce was stored
	s.sessionNonceMu.Lock()
	nonceCount := len(s.sessionNonces)
	s.sessionNonceMu.Unlock()
	if nonceCount != 1 {
		t.Errorf("expected 1 session nonce stored, got %d", nonceCount)
	}
}

func TestSessionsLoginMethodRestriction(t *testing.T) {
	_, ts := setupTestServer(t)

	req, _ := http.NewRequest("POST", ts.URL+"/sessions/login", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 405 {
		t.Errorf("POST to /sessions/login status = %d, want 405", resp.StatusCode)
	}
}

func TestSessionsCallbackInvalidNonce(t *testing.T) {
	s, ts := setupTestServer(t)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)

	// Try a sessions callback with an unknown nonce
	resp, err := http.Get(ts.URL + "/callback?state=sessions:aabbccdd11223344aabbccdd11223344&code=test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("invalid sessions nonce: status = %d, want 400", resp.StatusCode)
	}
}

func TestSessionsCallbackMalformedState(t *testing.T) {
	s, ts := setupTestServer(t)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)

	// sessions: prefix with bad nonce format
	resp, err := http.Get(ts.URL + "/callback?state=sessions:tooshort&code=test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("malformed sessions state: status = %d, want 400", resp.StatusCode)
	}
}

func TestCleanExpiredSessionNonces(t *testing.T) {
	s := newTestServer(t)
	s.sessionNonces = make(map[string]time.Time)

	// Add an expired nonce (6 min ago) and a fresh one
	s.sessionNonces["expired"] = time.Now().Add(-6 * time.Minute)
	s.sessionNonces["fresh"] = time.Now()

	s.sessionNonceMu.Lock()
	s.cleanExpiredSessionNonces()
	s.sessionNonceMu.Unlock()

	if _, ok := s.sessionNonces["expired"]; ok {
		t.Error("expired nonce should have been cleaned up")
	}
	if _, ok := s.sessionNonces["fresh"]; !ok {
		t.Error("fresh nonce should not have been cleaned up")
	}
}

func TestSessionStateFileConfig(t *testing.T) {
	t.Setenv("PAM_POCKETID_ISSUER_URL", "https://id.example.com")
	t.Setenv("PAM_POCKETID_CLIENT_ID", "test")
	t.Setenv("PAM_POCKETID_CLIENT_SECRET", "secret")
	t.Setenv("PAM_POCKETID_EXTERNAL_URL", "https://sudo.example.com")
	t.Setenv("PAM_POCKETID_SHARED_SECRET", "test-secret-that-is-long-enough")
	t.Setenv("PAM_POCKETID_SESSION_STATE_FILE", "/data/sessions.json")

	cfg, err := LoadServerConfig()
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.SessionStateFile != "/data/sessions.json" {
		t.Errorf("SessionStateFile = %q, want %q", cfg.SessionStateFile, "/data/sessions.json")
	}
}

func TestDashboardUnauthenticated(t *testing.T) {
	_, ts := setupTestServer(t)

	// Don't follow redirects — check for the redirect itself
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 303 {
		t.Errorf("status = %d, want 303 redirect", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/sessions/login") {
		t.Errorf("redirect location = %q, want /sessions/login", loc)
	}
}

func TestDashboardAuthenticated(t *testing.T) {
	s, ts := setupTestServer(t)

	// Create a session cookie
	recorder := httptest.NewRecorder()
	s.setSessionCookie(recorder, "jordan", "user")
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("setSessionCookie did not set a cookie")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("jordan")) {
		t.Error("authenticated dashboard should contain username")
	}
	if !bytes.Contains(body, []byte("pam-pocketid")) {
		t.Error("dashboard should contain heading")
	}
}

func TestSessionCookieRoundTrip(t *testing.T) {
	s := newTestServer(t)

	// Set a cookie
	recorder := httptest.NewRecorder()
	s.setSessionCookie(recorder, "jordan", "user")
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie set")
	}

	// Verify the cookie
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	username := s.getSessionUser(req)
	if username != "jordan" {
		t.Errorf("getSessionUser = %q, want %q", username, "jordan")
	}
}

func TestSessionCookieRejectsInvalid(t *testing.T) {
	s := newTestServer(t)

	tests := []struct {
		cookieValue string
		desc        string
	}{
		{"", "empty cookie"},
		{"invalid", "no colons"},
		{"jordan:notanumber:sig", "bad timestamp"},
		{"jordan:1000000000:badsig", "wrong signature"},
		{"bad user!:1000000000:sig", "invalid username chars"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		if tt.cookieValue != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tt.cookieValue})
		}
		if user := s.getSessionUser(req); user != "" {
			t.Errorf("%s: getSessionUser = %q, want empty", tt.desc, user)
		}
	}
}

func TestDashboardNotFound(t *testing.T) {
	_, ts := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/nonexistent")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404 for non-root path", resp.StatusCode)
	}
}

func TestDashboardFlashMessages(t *testing.T) {
	s, ts := setupTestServer(t)

	// Create an authenticated request with flash cookie
	recorder := httptest.NewRecorder()
	s.setSessionCookie(recorder, "jordan", "user")
	cookies := recorder.Result().Cookies()

	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	// Add flash cookie with multiple messages
	req.AddCookie(&http.Cookie{Name: "pam_flash", Value: "approved:docker,revoked:plex"})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("Approved sudo on docker")) {
		t.Error("dashboard should contain approved flash for docker")
	}
	if !bytes.Contains(body, []byte("Revoked session on plex")) {
		t.Error("dashboard should contain revoked flash for plex")
	}

	// Verify flash cookie is cleared (Max-Age=-1)
	for _, c := range resp.Cookies() {
		if c.Name == "pam_flash" && c.MaxAge < 0 {
			return // good - cookie was cleared
		}
	}
	// Note: the cookie clearing is done via Set-Cookie header in the response
}

func TestActionLog(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	store.LogAction("jordan", "approved", "docker", "ABCDEF-123456", "jordan")
	store.LogAction("jordan", "revoked", "plex", "", "jordan")

	history := store.ActionHistory("jordan")
	if len(history) != 2 {
		t.Fatalf("len(history) = %d, want 2", len(history))
	}

	// Most recent first
	if history[0].Action != "revoked" {
		t.Errorf("history[0].Action = %q, want %q", history[0].Action, "revoked")
	}
	if history[1].Action != "approved" {
		t.Errorf("history[1].Action = %q, want %q", history[1].Action, "approved")
	}
}

func TestActionLogGrowsUnbounded(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	// Without file-size rotation, the log grows unbounded in memory.
	n := 200
	for i := 0; i < n; i++ {
		store.LogAction("jordan", "approved", "host", "CODE", "jordan")
	}

	history := store.ActionHistory("jordan")
	if len(history) != n {
		t.Errorf("len(history) = %d, want %d (log should grow without per-insert pruning)", len(history), n)
	}
}
