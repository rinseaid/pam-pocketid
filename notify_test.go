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

// newNotifyTestServer creates a test server with a notify command and returns
// cleanup and wait helpers. The wait function drains in-flight notifications
// deterministically (no time.Sleep).
func newNotifyTestServer(t *testing.T, cfg *Config) (*Server, *httptest.Server) {
	t.Helper()
	s := &Server{
		cfg:          cfg,
		store:        NewChallengeStore(cfg.ChallengeTTL, cfg.GracePeriod, ""),
		hostRegistry: NewHostRegistry(""),
		mux:          http.NewServeMux(),
	}
	s.mux.HandleFunc("/api/challenge", s.handleCreateChallenge)
	ts := httptest.NewServer(s)
	t.Cleanup(func() {
		ts.Close()
		s.WaitForNotifications(5 * time.Second)
		s.store.Stop()
	})
	return s, ts
}

func createChallenge(t *testing.T, tsURL, username, hostname string) (challengeID, userCode, verificationURL string) {
	t.Helper()
	payload := `{"username":"` + username + `"`
	if hostname != "" {
		payload += `,"hostname":"` + hostname + `"`
	}
	payload += `}`
	body := bytes.NewBufferString(payload)
	req, _ := http.NewRequest("POST", tsURL+"/api/challenge", body)
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

	var cr struct {
		ChallengeID     string `json:"challenge_id"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
		Status          string `json:"status"`
	}
	json.NewDecoder(resp.Body).Decode(&cr)
	return cr.ChallengeID, cr.UserCode, cr.VerificationURL
}

func TestNotifyCommandFired(t *testing.T) {
	tmp, err := os.CreateTemp("", "notify-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:  "http://localhost:8090",
		SharedSecret: "test-secret-that-is-long-enough",
		ChallengeTTL: 120 * time.Second,
		NotifyCommand: "echo \"$NOTIFY_USERNAME $NOTIFY_HOSTNAME $NOTIFY_USER_CODE $NOTIFY_APPROVAL_URL $NOTIFY_EXPIRES_IN\" > " + tmp.Name(),
	})

	_, userCode, verificationURL := createChallenge(t, ts.URL, "alice", "prod-1")

	s.WaitForNotifications(5 * time.Second)

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("reading notify output: %v", err)
	}
	output := strings.TrimSpace(string(data))
	if !strings.Contains(output, "alice") {
		t.Errorf("notify output missing username, got: %s", output)
	}
	if !strings.Contains(output, "prod-1") {
		t.Errorf("notify output missing hostname, got: %s", output)
	}
	if !strings.Contains(output, userCode) {
		t.Errorf("notify output missing user code %s, got: %s", userCode, output)
	}
	if !strings.Contains(output, verificationURL) {
		t.Errorf("notify output missing approval URL, got: %s", output)
	}
	if !strings.Contains(output, "120") {
		t.Errorf("notify output missing NOTIFY_EXPIRES_IN=120, got: %s", output)
	}
}

func TestNotifyEmptyHostname(t *testing.T) {
	tmp, err := os.CreateTemp("", "notify-empty-host-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:  "http://localhost:8090",
		SharedSecret: "test-secret-that-is-long-enough",
		ChallengeTTL: 120 * time.Second,
		NotifyCommand: "echo \"user=$NOTIFY_USERNAME host=$NOTIFY_HOSTNAME\" > " + tmp.Name(),
	})

	createChallenge(t, ts.URL, "alice", "")

	s.WaitForNotifications(5 * time.Second)

	data, _ := os.ReadFile(tmp.Name())
	output := strings.TrimSpace(string(data))
	if !strings.Contains(output, "user=alice") {
		t.Errorf("expected user=alice, got: %s", output)
	}
	// hostname should be empty but command should still succeed
	if !strings.Contains(output, "host=") {
		t.Errorf("expected host= (empty), got: %s", output)
	}
}

func TestNotifyNotFiredOnGracePeriod(t *testing.T) {
	tmp, err := os.CreateTemp("", "notify-grace-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:  "http://localhost:8090",
		SharedSecret: "test-secret-that-is-long-enough",
		ChallengeTTL: 120 * time.Second,
		GracePeriod:  5 * time.Minute,
		NotifyCommand: "echo fired > " + tmp.Name(),
	})

	// First challenge — notification fires.
	createChallenge(t, ts.URL, "bob", "dev-1")

	// Second challenge — approve it to seed grace period.
	challengeID, _, _ := createChallenge(t, ts.URL, "bob", "dev-1")
	s.store.Approve(challengeID, "bob")

	// Wait for notifications from first two challenges.
	s.WaitForNotifications(5 * time.Second)

	// Verify notification DID fire for the first two.
	data, _ := os.ReadFile(tmp.Name())
	if strings.TrimSpace(string(data)) != "fired" {
		t.Fatal("notification should have fired for non-grace-period challenge")
	}

	// Clear the marker file.
	os.WriteFile(tmp.Name(), []byte(""), 0644)

	// Third challenge — should be auto-approved via grace period (no notification).
	body := bytes.NewBufferString(`{"username":"bob","hostname":"dev-1"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/challenge", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret-that-is-long-enough")
	resp, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var graceResp struct {
		Status string `json:"status"`
	}
	json.Unmarshal(b, &graceResp)
	if graceResp.Status != "approved" {
		t.Fatalf("expected auto-approved, got status=%q body=%s", graceResp.Status, string(b))
	}

	// Wait and verify the notification was NOT fired.
	s.WaitForNotifications(5 * time.Second)
	data, _ = os.ReadFile(tmp.Name())
	if strings.TrimSpace(string(data)) == "fired" {
		t.Error("notification was sent for grace-period auto-approval, should have been skipped")
	}
}

func TestNotifyNoopWithoutConfig(t *testing.T) {
	_, ts := newNotifyTestServer(t, &Config{
		ExternalURL:  "http://localhost:8090",
		SharedSecret: "test-secret-that-is-long-enough",
		ChallengeTTL: 120 * time.Second,
		// NotifyCommand intentionally empty
	})

	createChallenge(t, ts.URL, "carol", "")
	// No panic, no error — that's the test.
}

func TestNotifyEnvPassthrough(t *testing.T) {
	tmp, err := os.CreateTemp("", "notify-env-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	os.Setenv("APPRISE_TEST_VAR", "hello-apprise")
	defer os.Unsetenv("APPRISE_TEST_VAR")

	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:          "http://localhost:8090",
		SharedSecret:         "test-secret-that-is-long-enough",
		ChallengeTTL:         120 * time.Second,
		NotifyCommand:        "echo $APPRISE_TEST_VAR > " + tmp.Name(),
		NotifyEnvPassthrough: []string{"APPRISE_"},
	})

	createChallenge(t, ts.URL, "dave", "")

	s.WaitForNotifications(5 * time.Second)

	data, _ := os.ReadFile(tmp.Name())
	if strings.TrimSpace(string(data)) != "hello-apprise" {
		t.Errorf("expected APPRISE_TEST_VAR passed through, got: %q", strings.TrimSpace(string(data)))
	}
}

func TestNotifyEnvExclusion(t *testing.T) {
	// Verify that non-prefixed env vars and server secrets are NOT passed.
	tmp, err := os.CreateTemp("", "notify-excl-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	// Simulate server secrets that should NOT leak.
	os.Setenv("PAM_POCKETID_CLIENT_SECRET", "super-secret-value")
	os.Setenv("UNRELATED_SECRET", "should-not-leak")
	os.Setenv("APPRISE_ALLOWED", "this-is-ok")
	defer os.Unsetenv("PAM_POCKETID_CLIENT_SECRET")
	defer os.Unsetenv("UNRELATED_SECRET")
	defer os.Unsetenv("APPRISE_ALLOWED")

	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:          "http://localhost:8090",
		SharedSecret:         "test-secret-that-is-long-enough",
		ChallengeTTL:         120 * time.Second,
		NotifyCommand:        "env > " + tmp.Name(),
		NotifyEnvPassthrough: []string{"APPRISE_"},
	})

	createChallenge(t, ts.URL, "eve", "")

	s.WaitForNotifications(5 * time.Second)

	data, _ := os.ReadFile(tmp.Name())
	output := string(data)

	// Should be present
	if !strings.Contains(output, "APPRISE_ALLOWED=this-is-ok") {
		t.Error("APPRISE_ALLOWED should be passed through")
	}
	if !strings.Contains(output, "NOTIFY_USERNAME=eve") {
		t.Error("NOTIFY_USERNAME should be set")
	}

	// Should NOT be present
	if strings.Contains(output, "PAM_POCKETID_CLIENT_SECRET") {
		t.Error("PAM_POCKETID_CLIENT_SECRET leaked to notify command")
	}
	if strings.Contains(output, "UNRELATED_SECRET") {
		t.Error("UNRELATED_SECRET leaked to notify command")
	}
}

func TestNotifyCommandFailure(t *testing.T) {
	// Verify that a failing notify command doesn't panic or block.
	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:  "http://localhost:8090",
		SharedSecret: "test-secret-that-is-long-enough",
		ChallengeTTL: 120 * time.Second,
		NotifyCommand: "exit 1",
	})

	createChallenge(t, ts.URL, "frank", "host-1")

	// Should complete without panic.
	s.WaitForNotifications(5 * time.Second)
}

func TestNotifyCommandTimeout(t *testing.T) {
	// Verify that a hung notify command is killed by the timeout.
	// We use a shorter timeout to keep the test fast.
	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:  "http://localhost:8090",
		SharedSecret: "test-secret-that-is-long-enough",
		ChallengeTTL: 120 * time.Second,
		NotifyCommand: "sleep 60",
	})

	createChallenge(t, ts.URL, "grace", "host-1")

	// WaitForNotifications should return after notifyTimeout (15s).
	// In practice cmd.Run() will return as soon as the context cancels.
	// Use very generous timeouts to avoid flakes on slow CI runners with -race,
	// where process cleanup can take significantly longer than wall-clock time.
	done := make(chan struct{})
	go func() {
		s.WaitForNotifications(90 * time.Second)
		close(done)
	}()

	select {
	case <-done:
		// Good — completed within timeout.
	case <-time.After(90 * time.Second):
		t.Fatal("notify goroutine did not complete within 90s — timeout not working")
	}
}

func TestLimitedWriter(t *testing.T) {
	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, n: 10}

	// Write within limit
	n, err := lw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Errorf("first write: n=%d err=%v", n, err)
	}

	// Write that exceeds limit — truncates to buffer but reports full len(p)
	// to avoid short-write errors from exec.Cmd.
	n, err = lw.Write([]byte("worldextra"))
	if err != nil || n != 10 {
		t.Errorf("second write: n=%d err=%v", n, err)
	}

	// Write after exhaustion — should discard entirely but report full len(p)
	n, err = lw.Write([]byte("discarded"))
	if err != nil || n != 9 {
		t.Errorf("third write: n=%d err=%v", n, err)
	}

	// Only "hello" + "world" should be in the buffer (10 bytes)
	if buf.String() != "helloworld" {
		t.Errorf("expected 'helloworld', got %q", buf.String())
	}
}

func TestLookupUserURLs(t *testing.T) {
	users := map[string]string{
		"hazely": "tgram://bot/111",
		"sunny":  "tgram://bot/222 ntfy://ntfy.sh/sunny",
		"*":      "slack://fallback",
	}

	// Exact match
	if got := lookupUserURLs(users, "hazely"); got != "tgram://bot/111" {
		t.Errorf("hazely: got %q", got)
	}

	// Multi-URL match
	if got := lookupUserURLs(users, "sunny"); got != "tgram://bot/222 ntfy://ntfy.sh/sunny" {
		t.Errorf("sunny: got %q", got)
	}

	// Wildcard fallback
	if got := lookupUserURLs(users, "unknown"); got != "slack://fallback" {
		t.Errorf("unknown: got %q", got)
	}

	// No wildcard
	noWildcard := map[string]string{"hazely": "tgram://bot/111"}
	if got := lookupUserURLs(noWildcard, "unknown"); got != "" {
		t.Errorf("no wildcard: got %q", got)
	}

	// Nil map
	if got := lookupUserURLs(nil, "hazely"); got != "" {
		t.Errorf("nil map: got %q", got)
	}
}

func TestLoadNotifyUsers(t *testing.T) {
	// Valid file
	tmp, err := os.CreateTemp("", "notify-users-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	content := `{"hazely": "tgram://bot/111", "sunny": "ntfy://ntfy.sh/sunny", "*": "slack://ops"}`
	os.WriteFile(tmp.Name(), []byte(content), 0600)

	users := loadNotifyUsers(tmp.Name())
	if users == nil {
		t.Fatal("expected non-nil map")
	}
	if users["hazely"] != "tgram://bot/111" {
		t.Errorf("hazely: got %q", users["hazely"])
	}
	if users["*"] != "slack://ops" {
		t.Errorf("wildcard: got %q", users["*"])
	}

	// Empty path
	if got := loadNotifyUsers(""); got != nil {
		t.Error("empty path should return nil")
	}

	// Missing file
	if got := loadNotifyUsers("/nonexistent/path.json"); got != nil {
		t.Error("missing file should return nil")
	}

	// Invalid JSON
	badTmp, _ := os.CreateTemp("", "notify-bad-*.json")
	defer os.Remove(badTmp.Name())
	os.WriteFile(badTmp.Name(), []byte("not json"), 0600)
	if got := loadNotifyUsers(badTmp.Name()); got != nil {
		t.Error("invalid JSON should return nil")
	}
}

func TestNotifyPerUserURLs(t *testing.T) {
	// Create a users mapping file
	usersFile, err := os.CreateTemp("", "notify-users-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(usersFile.Name())
	os.WriteFile(usersFile.Name(), []byte(`{"hazely": "tgram://bot/111", "*": "slack://ops"}`), 0600)

	// Create a temp file to capture the env output
	tmp, err := os.CreateTemp("", "notify-peruser-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:     "http://localhost:8090",
		SharedSecret:    "test-secret-that-is-long-enough",
		ChallengeTTL:    120 * time.Second,
		NotifyCommand:   "env > " + tmp.Name(),
		NotifyUsersFile: usersFile.Name(),
	})

	createChallenge(t, ts.URL, "hazely", "web-prod-1")
	s.WaitForNotifications(5 * time.Second)

	data, _ := os.ReadFile(tmp.Name())
	output := string(data)

	if !strings.Contains(output, "NOTIFY_USER_URLS=tgram://bot/111") {
		t.Errorf("expected per-user URL for hazely, got env:\n%s", output)
	}
}

func TestNotifyPerUserWildcardFallback(t *testing.T) {
	usersFile, err := os.CreateTemp("", "notify-users-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(usersFile.Name())
	os.WriteFile(usersFile.Name(), []byte(`{"hazely": "tgram://bot/111", "*": "slack://ops"}`), 0600)

	tmp, err := os.CreateTemp("", "notify-wildcard-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:     "http://localhost:8090",
		SharedSecret:    "test-secret-that-is-long-enough",
		ChallengeTTL:    120 * time.Second,
		NotifyCommand:   "env > " + tmp.Name(),
		NotifyUsersFile: usersFile.Name(),
	})

	// "unknown" user should get wildcard "*" URLs
	createChallenge(t, ts.URL, "unknown", "host-1")
	s.WaitForNotifications(5 * time.Second)

	data, _ := os.ReadFile(tmp.Name())
	output := string(data)

	if !strings.Contains(output, "NOTIFY_USER_URLS=slack://ops") {
		t.Errorf("expected wildcard URL for unknown user, got env:\n%s", output)
	}
}

func TestNotifyPerUserNoFile(t *testing.T) {
	// When no users file is configured, NOTIFY_USER_URLS should be empty
	tmp, err := os.CreateTemp("", "notify-nofile-*")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	s, ts := newNotifyTestServer(t, &Config{
		ExternalURL:  "http://localhost:8090",
		SharedSecret: "test-secret-that-is-long-enough",
		ChallengeTTL: 120 * time.Second,
		NotifyCommand: "env > " + tmp.Name(),
		// NotifyUsersFile intentionally empty
	})

	createChallenge(t, ts.URL, "hazely", "host-1")
	s.WaitForNotifications(5 * time.Second)

	data, _ := os.ReadFile(tmp.Name())
	output := string(data)

	if !strings.Contains(output, "NOTIFY_USER_URLS=\n") && !strings.Contains(output, "NOTIFY_USER_URLS=\r") {
		// Check it's present but empty
		lines := strings.Split(output, "\n")
		found := false
		for _, line := range lines {
			if strings.HasPrefix(line, "NOTIFY_USER_URLS=") {
				val := strings.TrimPrefix(line, "NOTIFY_USER_URLS=")
				val = strings.TrimSpace(val)
				if val != "" {
					t.Errorf("expected empty NOTIFY_USER_URLS, got %q", val)
				}
				found = true
				break
			}
		}
		if !found {
			t.Error("NOTIFY_USER_URLS not found in env output")
		}
	}
}
