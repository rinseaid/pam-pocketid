package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerateBreakglassPassword_Random(t *testing.T) {
	pw, err := generateBreakglassPassword("random")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// base64url of 32 bytes = 43 chars (no padding with RawURLEncoding)
	if len(pw) != 43 {
		t.Errorf("expected 43 chars, got %d: %q", len(pw), pw)
	}
	// Should decode back to 32 bytes
	decoded, err := base64.RawURLEncoding.DecodeString(pw)
	if err != nil {
		t.Fatalf("not valid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("expected 32 decoded bytes, got %d", len(decoded))
	}
}

func TestGenerateBreakglassPassword_Passphrase(t *testing.T) {
	pw, err := generateBreakglassPassword("passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	words := strings.Split(pw, "-")
	if len(words) != 10 {
		t.Errorf("expected 10 words, got %d: %q", len(words), pw)
	}
	for _, w := range words {
		if len(w) < 2 || len(w) > 8 {
			t.Errorf("word %q has unexpected length", w)
		}
	}
}

func TestGenerateBreakglassPassword_Alphanumeric(t *testing.T) {
	pw, err := generateBreakglassPassword("alphanumeric")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pw) != 24 {
		t.Errorf("expected 24 chars, got %d: %q", len(pw), pw)
	}
	for _, c := range pw {
		if !strings.ContainsRune(unambiguousAlphanum, c) {
			t.Errorf("unexpected character %c in password", c)
		}
	}
}

func TestGenerateBreakglassPassword_Unknown(t *testing.T) {
	_, err := generateBreakglassPassword("invalid")
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestGenerateBreakglassPassword_Uniqueness(t *testing.T) {
	// Generate several passwords and verify they're all different
	for _, typ := range []string{"random", "passphrase", "alphanumeric"} {
		seen := make(map[string]bool)
		for i := 0; i < 10; i++ {
			pw, err := generateBreakglassPassword(typ)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", typ, err)
			}
			if seen[pw] {
				t.Errorf("%s: duplicate password generated: %q", typ, pw)
			}
			seen[pw] = true
		}
	}
}

func TestBreakglassFileWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass")

	hash := "$2a$12$testhashaaaaabbbbccccdddddd"
	if err := writeBreakglassFile(path, hash, "testhost", "random"); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Verify file exists and has correct permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("expected mode 0600, got %04o", mode)
	}

	// Verify contents: should have a comment header line followed by the hash
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "# pam-pocketid breakglass host=testhost type=random created=") {
		t.Errorf("expected metadata header, got %q", content)
	}
	if !strings.Contains(content, hash) {
		t.Errorf("expected hash %q in content %q", hash, content)
	}
}

func TestBreakglassFileWrite_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "breakglass")

	// Write initial content
	if err := writeBreakglassFile(path, "$2a$12$first", "testhost", "random"); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Overwrite with new content
	if err := writeBreakglassFile(path, "$2a$12$second", "testhost", "random"); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !strings.Contains(string(data), "$2a$12$second") {
		t.Errorf("expected second hash in content, got %q", string(data))
	}
}

func TestBreakglassFileRead(t *testing.T) {
	// Override fileOwnerUID for testing (tests don't run as root)
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()

	t.Run("valid hash file", func(t *testing.T) {
		path := filepath.Join(dir, "valid")
		hash := "$2a$12$K4IHxR8vXqT.XE4PmAuLOeUoUjT0g1v2GkA4mGdN4SIxlJPKCpOy"
		os.WriteFile(path, []byte(hash+"\n"), 0600)

		got, err := readBreakglassHash(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != hash {
			t.Errorf("expected %q, got %q", hash, got)
		}
	})

	t.Run("wrong permissions", func(t *testing.T) {
		path := filepath.Join(dir, "wrongperm")
		os.WriteFile(path, []byte("$2a$12$hash\n"), 0644)

		_, err := readBreakglassHash(path)
		if err == nil {
			t.Fatal("expected error for wrong permissions")
		}
		if !strings.Contains(err.Error(), "group/other permissions") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("wrong owner", func(t *testing.T) {
		fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 1000, true }
		defer func() { fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true } }()

		path := filepath.Join(dir, "wrongowner")
		os.WriteFile(path, []byte("$2a$12$hash\n"), 0600)

		_, err := readBreakglassHash(path)
		if err == nil {
			t.Fatal("expected error for wrong owner")
		}
		if !strings.Contains(err.Error(), "not owned by root") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("symlink rejected", func(t *testing.T) {
		realPath := filepath.Join(dir, "real")
		os.WriteFile(realPath, []byte("$2a$12$hash\n"), 0600)
		linkPath := filepath.Join(dir, "symlink")
		os.Symlink(realPath, linkPath)

		_, err := readBreakglassHash(linkPath)
		if err == nil {
			t.Fatal("expected error for symlink")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(dir, "empty")
		os.WriteFile(path, []byte(""), 0600)

		_, err := readBreakglassHash(path)
		if err == nil {
			t.Fatal("expected error for empty file")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("not bcrypt hash", func(t *testing.T) {
		path := filepath.Join(dir, "notbcrypt")
		os.WriteFile(path, []byte("notahash\n"), 0600)

		_, err := readBreakglassHash(path)
		if err == nil {
			t.Fatal("expected error for non-bcrypt content")
		}
		if !strings.Contains(err.Error(), "valid bcrypt") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := readBreakglassHash(filepath.Join(dir, "nonexistent"))
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}

func TestBreakglassVerify(t *testing.T) {
	password := "test-break-glass-password"
	hash, err := hashBreakglassPassword(password)
	if err != nil {
		t.Fatalf("hashing failed: %v", err)
	}

	t.Run("correct password", func(t *testing.T) {
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
			t.Errorf("correct password rejected: %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong")); err == nil {
			t.Error("wrong password accepted")
		}
	})

	t.Run("empty password", func(t *testing.T) {
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("")); err == nil {
			t.Error("empty password accepted")
		}
	})
}

func TestIsServerUnreachable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "net.OpError (connection refused)",
			err:      fmt.Errorf("connecting to auth server: %w", &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")}),
			expected: true,
		},
		{
			name:     "net.DNSError",
			err:      fmt.Errorf("connecting to auth server: %w", &net.DNSError{Err: "no such host", Name: "auth.example.com"}),
			expected: true,
		},
		{
			name:     "context deadline exceeded (slow server, NOT unreachable)",
			err:      fmt.Errorf("connecting to auth server: %w", context.DeadlineExceeded),
			expected: false,
		},
		{
			name:     "wrapped net.OpError (dial)",
			err:      fmt.Errorf("creating challenge: %w", fmt.Errorf("connecting to auth server: %w", &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("network is unreachable")})),
			expected: true,
		},
		{
			name:     "net.OpError read (server accepted TCP then reset — NOT unreachable)",
			err:      fmt.Errorf("connecting to auth server: %w", &net.OpError{Op: "read", Net: "tcp", Err: fmt.Errorf("connection reset by peer")}),
			expected: false,
		},
		{
			name:     "HTTP 500 error",
			err:      &serverHTTPError{StatusCode: 500, Body: "internal error"},
			expected: false,
		},
		{
			name:     "HTTP 401 error",
			err:      &serverHTTPError{StatusCode: 401, Body: "unauthorized"},
			expected: false,
		},
		{
			name:     "HTTP 429 error",
			err:      &serverHTTPError{StatusCode: 429, Body: "rate limit"},
			expected: false,
		},
		{
			name:     "wrapped server HTTP error",
			err:      fmt.Errorf("creating challenge: %w", &serverHTTPError{StatusCode: 500, Body: "err"}),
			expected: false,
		},
		{
			name: "HTTP error with connection refused in body (should NOT trigger fallback)",
			err:  &serverHTTPError{StatusCode: 500, Body: "connection refused"},
			expected: false,
		},
		{
			name:     "HTTP 404 Not Found (reverse proxy, no backend route)",
			err:      &serverHTTPError{StatusCode: 404, Body: "404 page not found"},
			expected: true,
		},
		{
			name:     "HTTP 502 Bad Gateway (reverse proxy, backend down)",
			err:      &serverHTTPError{StatusCode: 502, Body: "Bad Gateway"},
			expected: true,
		},
		{
			name:     "HTTP 503 Service Unavailable (reverse proxy, backend down)",
			err:      &serverHTTPError{StatusCode: 503, Body: "Service Unavailable"},
			expected: true,
		},
		{
			name:     "HTTP 504 Gateway Timeout (reverse proxy, backend unresponsive)",
			err:      &serverHTTPError{StatusCode: 504, Body: "Gateway Timeout"},
			expected: true,
		},
		{
			name:     "wrapped HTTP 502 error",
			err:      fmt.Errorf("creating challenge: %w", &serverHTTPError{StatusCode: 502, Body: "Bad Gateway"}),
			expected: true,
		},
		{
			name:     "generic error",
			err:      fmt.Errorf("some other error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isServerUnreachable(tt.err)
			if got != tt.expected {
				t.Errorf("isServerUnreachable(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestAuthenticateBreakglassFallback(t *testing.T) {
	// Set up: create a break-glass file with a known password
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass")
	password := "test-fallback-password"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	os.WriteFile(hashFile, []byte(string(hash)+"\n"), 0600)

	// Mock /dev/tty and readPasswordFn
	origOpenTTY := openTTY
	origReadPW := readPasswordFn
	defer func() {
		openTTY = origOpenTTY
		readPasswordFn = origReadPW
	}()

	// Use a pipe for the TTY (writes go to /dev/null)
	r, w, _ := os.Pipe()
	w.Close()
	openTTY = func() (*os.File, error) { return r, nil }

	// Override readPasswordFn to return our test password
	readPasswordFn = func(fd int) ([]byte, error) {
		return []byte(password), nil
	}

	// Capture messageWriter output
	origMW := messageWriter
	messageWriter = io.Discard
	defer func() { messageWriter = origMW }()

	// Test: start an unreachable server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close() // Close immediately so it's unreachable

	cfg := &Config{
		ServerURL:         "http://" + addr,
		SharedSecret:      "test-secret-1234567890",
		PollInterval:      time.Second,
		Timeout:           5 * time.Second,
		BreakglassEnabled: true,
		BreakglassFile:    hashFile,
	}

	client := NewPAMClient(cfg, nil)
	err = client.Authenticate("testuser")
	if err != nil {
		t.Fatalf("expected break-glass success, got: %v", err)
	}
}

func TestBreakglassNotTriggeredOnHTTPError(t *testing.T) {
	// Set up: server is reachable but returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Create a break-glass file (should NOT be used)
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass")
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	os.WriteFile(hashFile, []byte(string(hash)+"\n"), 0600)

	origMW := messageWriter
	messageWriter = io.Discard
	defer func() { messageWriter = origMW }()

	cfg := &Config{
		ServerURL:         srv.URL,
		SharedSecret:      "test-secret-1234567890",
		PollInterval:      time.Second,
		Timeout:           5 * time.Second,
		BreakglassEnabled: true,
		BreakglassFile:    hashFile,
	}

	client := NewPAMClient(cfg, nil)
	err := client.Authenticate("testuser")
	if err == nil {
		t.Fatal("expected error when server returns 500")
	}
	// Should get the HTTP error, not break-glass
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected HTTP 500 error, got: %v", err)
	}
}

func TestEscrowEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		escrowCommand  string
		sharedSecret   string
		requestSecret  string
		body           string
		expectedStatus int
		expectContains string
	}{
		{
			name:           "no escrow command configured",
			escrowCommand:  "",
			sharedSecret:   "test-secret-1234567890",
			requestSecret:  "test-secret-1234567890",
			body:           `{"hostname":"host1","password":"secret123"}`,
			expectedStatus: 501,
			expectContains: "escrow not configured",
		},
		{
			name:           "successful escrow",
			escrowCommand:  "cat > /dev/null",
			sharedSecret:   "test-secret-1234567890",
			requestSecret:  "test-secret-1234567890",
			body:           `{"hostname":"host1","password":"secret123"}`,
			expectedStatus: 200,
			expectContains: "ok",
		},
		{
			name:           "auth failure",
			escrowCommand:  "cat > /dev/null",
			sharedSecret:   "test-secret-1234567890",
			requestSecret:  "wrong-secret-1234567",
			body:           `{"hostname":"host1","password":"secret123"}`,
			expectedStatus: 401,
		},
		{
			name:           "missing password",
			escrowCommand:  "cat > /dev/null",
			sharedSecret:   "test-secret-1234567890",
			requestSecret:  "test-secret-1234567890",
			body:           `{"hostname":"host1"}`,
			expectedStatus: 400,
		},
		{
			name:           "invalid hostname",
			escrowCommand:  "cat > /dev/null",
			sharedSecret:   "test-secret-1234567890",
			requestSecret:  "test-secret-1234567890",
			body:           `{"hostname":"host with spaces","password":"secret"}`,
			expectedStatus: 400,
		},
		{
			name:           "escrow command fails",
			escrowCommand:  "exit 1",
			sharedSecret:   "test-secret-1234567890",
			requestSecret:  "test-secret-1234567890",
			body:           `{"hostname":"host1","password":"secret123"}`,
			expectedStatus: 500,
		},
		{
			name:           "no shared secret (INSECURE mode) blocked",
			escrowCommand:  "cat > /dev/null",
			sharedSecret:   "",
			requestSecret:  "",
			body:           `{"hostname":"host1","password":"secret123"}`,
			expectedStatus: 403,
			expectContains: "requires shared secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				SharedSecret:  tt.sharedSecret,
				EscrowCommand: tt.escrowCommand,
			}

			// Create a minimal server (without OIDC) just to test the handler
			s := &Server{
				cfg: cfg,
				mux: http.NewServeMux(),
			}
			s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)

			req := httptest.NewRequest(http.MethodPost, "/api/breakglass/escrow", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.requestSecret != "" {
				req.Header.Set("X-Shared-Secret", tt.requestSecret)
				// Parse hostname from body to compute per-host escrow token
				var parsed struct{ Hostname string }
				json.Unmarshal([]byte(tt.body), &parsed)
				if parsed.Hostname != "" {
					req.Header.Set("X-Escrow-Token", computeEscrowToken(tt.requestSecret, parsed.Hostname))
				}
			}
			w := httptest.NewRecorder()

			s.mux.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d (body: %s)", tt.expectedStatus, w.Code, w.Body.String())
			}
			if tt.expectContains != "" && !strings.Contains(w.Body.String(), tt.expectContains) {
				t.Errorf("expected body to contain %q, got %q", tt.expectContains, w.Body.String())
			}
		})
	}
}

func TestEscrowEndpoint_PasswordOnStdin(t *testing.T) {
	// Verify that the escrow command receives the password on stdin
	dir := t.TempDir()
	outFile := filepath.Join(dir, "password.txt")

	cfg := &Config{
		SharedSecret:  "test-secret-1234567890",
		EscrowCommand: fmt.Sprintf("cat > %s", outFile),
	}

	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)

	body := `{"hostname":"testhost","password":"my-secret-password"}`
	req := httptest.NewRequest(http.MethodPost, "/api/breakglass/escrow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret-1234567890")
	req.Header.Set("X-Escrow-Token", computeEscrowToken("test-secret-1234567890", "testhost"))
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify password was written by the command
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if string(data) != "my-secret-password" {
		t.Errorf("expected password on stdin, got %q", string(data))
	}
}

func TestEscrowEndpoint_EnvVars(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "env.txt")

	cfg := &Config{
		SharedSecret:  "test-secret-1234567890",
		EscrowCommand: fmt.Sprintf("env | grep BREAKGLASS > %s", outFile),
	}

	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)

	body := `{"hostname":"myhost.example.com","password":"pw"}`
	req := httptest.NewRequest(http.MethodPost, "/api/breakglass/escrow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret-1234567890")
	req.Header.Set("X-Escrow-Token", computeEscrowToken("test-secret-1234567890", "myhost.example.com"))
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading env file: %v", err)
	}
	envStr := string(data)
	if !strings.Contains(envStr, "BREAKGLASS_HOSTNAME=myhost.example.com") {
		t.Errorf("expected BREAKGLASS_HOSTNAME env var, got: %s", envStr)
	}
}

func TestEscrowEndpoint_MethodNotAllowed(t *testing.T) {
	s := &Server{cfg: &Config{SharedSecret: "test-secret-1234567890"}, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)

	req := httptest.NewRequest(http.MethodGet, "/api/breakglass/escrow", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestRotateBreakglassBefore(t *testing.T) {
	// Test that the server includes rotate_breakglass_before in challenge responses
	rotateBefore := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	cfg := &Config{
		SharedSecret:           "test-secret-1234567890",
		ChallengeTTL:           120 * time.Second,
		BreakglassRotateBefore: rotateBefore,
	}

	store := NewChallengeStore(cfg.ChallengeTTL, 0)
	defer store.Stop()

	s := &Server{cfg: cfg, store: store, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/challenge", s.handleCreateChallenge)

	body := `{"username":"testuser"}`
	req := httptest.NewRequest(http.MethodPost, "/api/challenge", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret-1234567890")
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	rbStr, ok := resp["rotate_breakglass_before"].(string)
	if !ok {
		t.Fatal("expected rotate_breakglass_before in response")
	}
	rbTime, err := time.Parse(time.RFC3339, rbStr)
	if err != nil {
		t.Fatalf("invalid time format: %v", err)
	}
	if !rbTime.Equal(rotateBefore) {
		t.Errorf("expected %v, got %v", rotateBefore, rbTime)
	}
}

func TestServerHTTPError(t *testing.T) {
	err := &serverHTTPError{StatusCode: 500, Body: "internal error"}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error string should contain status code: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "internal error") {
		t.Errorf("error string should contain body: %s", err.Error())
	}
}

func TestBreakglassFileExists(t *testing.T) {
	dir := t.TempDir()

	t.Run("exists", func(t *testing.T) {
		path := filepath.Join(dir, "exists")
		os.WriteFile(path, []byte("test"), 0600)
		if !breakglassFileExists(path) {
			t.Error("expected true for existing file")
		}
	})

	t.Run("not exists", func(t *testing.T) {
		if breakglassFileExists(filepath.Join(dir, "nonexistent")) {
			t.Error("expected false for nonexistent file")
		}
	})
}

func TestBreakglassFileAge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test")
	os.WriteFile(path, []byte("test"), 0600)

	age, err := breakglassFileAge(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// File was just created, age should be very small
	if age > 5*time.Second {
		t.Errorf("expected age < 5s, got %v", age)
	}
}

func TestHashBreakglassPassword(t *testing.T) {
	hash, err := hashBreakglassPassword("testpassword")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$12$") {
		t.Errorf("expected bcrypt cost 12 hash, got prefix: %s", hash[:7])
	}
	// Verify the hash works
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("testpassword")); err != nil {
		t.Error("hash doesn't match original password")
	}
}

// --- Tests for gaps identified by the security audit ---

func TestBreakglassFileExists_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real")
	os.WriteFile(realPath, []byte("test"), 0600)

	linkPath := filepath.Join(dir, "link")
	os.Symlink(realPath, linkPath)

	if breakglassFileExists(linkPath) {
		t.Error("breakglassFileExists should return false for symlinks (uses Lstat)")
	}
	// The real file should still return true
	if !breakglassFileExists(realPath) {
		t.Error("breakglassFileExists should return true for regular files")
	}
}

func TestBreakglassFileRead_WithMetadataHeader(t *testing.T) {
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()
	path := filepath.Join(dir, "with-header")
	hash := "$2a$12$K4IHxR8vXqT.XE4PmAuLOeUoUjT0g1v2GkA4mGdN4SIxlJPKCpOy"
	content := fmt.Sprintf("# pam-pocketid breakglass host=testhost type=random created=2025-01-01T00:00:00Z\n%s\n", hash)
	os.WriteFile(path, []byte(content), 0600)

	got, err := readBreakglassHash(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != hash {
		t.Errorf("expected %q, got %q", hash, got)
	}
}

func TestRotateBreakglass_EscrowBeforeHash(t *testing.T) {
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass")

	// Track order: did escrow happen before hash file was written?
	escrowCalled := false
	hashExistedDuringEscrow := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escrowCalled = true
		// Check if hash file exists at the time of escrow
		_, err := os.Stat(hashFile)
		hashExistedDuringEscrow = err == nil
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	cfg := &Config{
		ServerURL:              srv.URL,
		SharedSecret:           "test-secret-1234567890",
		BreakglassFile:         hashFile,
		BreakglassRotationDays: 90,
		BreakglassPasswordType: "random",
	}

	plaintext, err := rotateBreakglass(cfg, true)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if !escrowCalled {
		t.Fatal("escrow was not called")
	}
	if hashExistedDuringEscrow {
		t.Error("hash file existed during escrow — escrow should happen BEFORE hash write")
	}
	if plaintext != "" {
		t.Error("plaintext should be empty when escrow succeeds")
	}
	// Verify hash file was written after escrow
	if !breakglassFileExists(hashFile) {
		t.Fatal("hash file should exist after rotation")
	}
}

func TestRotateBreakglass_EscrowFailure_PreservesOldHash(t *testing.T) {
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass")

	// Write an initial hash
	oldHash := "$2a$12$initialhashabcdefghijklmnopqrstuvwxyz012345678"
	os.WriteFile(hashFile, []byte(oldHash+"\n"), 0600)

	// Server that returns 500 (non-501 error)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &Config{
		ServerURL:              srv.URL,
		SharedSecret:           "test-secret-1234567890",
		BreakglassFile:         hashFile,
		BreakglassRotationDays: 90,
		BreakglassPasswordType: "random",
	}

	_, err := rotateBreakglass(cfg, true)
	if err == nil {
		t.Fatal("expected error when escrow fails")
	}
	if !strings.Contains(err.Error(), "escrow failed") {
		t.Errorf("expected 'escrow failed' error, got: %v", err)
	}

	// Old hash should be preserved
	data, _ := os.ReadFile(hashFile)
	if !strings.Contains(string(data), oldHash) {
		t.Errorf("old hash should be preserved after escrow failure, got: %q", string(data))
	}
}

func TestRotateBreakglass_501_ReturnsPassword(t *testing.T) {
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass")

	// Server that returns 501 (no escrow command)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "escrow not configured on server", http.StatusNotImplemented)
	}))
	defer srv.Close()

	cfg := &Config{
		ServerURL:              srv.URL,
		SharedSecret:           "test-secret-1234567890",
		BreakglassFile:         hashFile,
		BreakglassRotationDays: 90,
		BreakglassPasswordType: "random",
	}

	plaintext, err := rotateBreakglass(cfg, true)
	if err != nil {
		t.Fatalf("expected success on 501 (non-fatal), got: %v", err)
	}
	if plaintext == "" {
		t.Error("expected plaintext password to be returned when escrow returns 501")
	}
	// Hash file should still be written
	if !breakglassFileExists(hashFile) {
		t.Fatal("hash file should exist after rotation even with 501")
	}
	// The returned password should match the hash
	hash, err := readBreakglassHash(hashFile)
	if err != nil {
		t.Fatalf("reading hash: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)); err != nil {
		t.Error("returned password does not match the written hash")
	}
}

func TestRotateBreakglass_NoServer_ReturnsPassword(t *testing.T) {
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass")

	cfg := &Config{
		ServerURL:              "", // No server
		BreakglassFile:         hashFile,
		BreakglassRotationDays: 90,
		BreakglassPasswordType: "passphrase",
	}

	plaintext, err := rotateBreakglass(cfg, true)
	if err != nil {
		t.Fatalf("expected success without server, got: %v", err)
	}
	if plaintext == "" {
		t.Error("expected plaintext password when no server configured")
	}
	// Passphrase should have dashes (10 words)
	if strings.Count(plaintext, "-") != 9 {
		t.Errorf("expected 9 dashes in passphrase (10 words), got %d in %q", strings.Count(plaintext, "-"), plaintext)
	}
}

func TestBreakglassNotTriggeredWhenDisabled(t *testing.T) {
	// Server is unreachable, hash file exists, but BreakglassEnabled=false
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "breakglass")
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	os.WriteFile(hashFile, []byte(string(hash)+"\n"), 0600)

	origMW := messageWriter
	messageWriter = io.Discard
	defer func() { messageWriter = origMW }()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	listener.Close()

	cfg := &Config{
		ServerURL:         "http://" + addr,
		SharedSecret:      "test-secret-1234567890",
		PollInterval:      time.Second,
		Timeout:           5 * time.Second,
		BreakglassEnabled: false, // DISABLED
		BreakglassFile:    hashFile,
	}

	client := NewPAMClient(cfg, nil)
	err := client.Authenticate("testuser")
	if err == nil {
		t.Fatal("expected error when break-glass is disabled")
	}
	// Should get a connection error, not break-glass
	if strings.Contains(err.Error(), "break-glass") {
		t.Errorf("break-glass should not trigger when disabled, got: %v", err)
	}
}

func TestEscrowEndpoint_EmptyHostnameRejected(t *testing.T) {
	cfg := &Config{
		SharedSecret:  "test-secret-1234567890",
		EscrowCommand: "cat > /dev/null",
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)

	body := `{"hostname":"","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/breakglass/escrow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret-1234567890")
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty hostname, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEscrowEndpoint_WrongEscrowToken(t *testing.T) {
	cfg := &Config{
		SharedSecret:  "test-secret-1234567890",
		EscrowCommand: "cat > /dev/null",
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)

	body := `{"hostname":"host1","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/breakglass/escrow", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", "test-secret-1234567890")
	// Set escrow token for a DIFFERENT hostname
	req.Header.Set("X-Escrow-Token", computeEscrowToken("test-secret-1234567890", "different-host"))
	w := httptest.NewRecorder()

	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wrong escrow token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestComputeEscrowToken_DeterministicAndHostBound(t *testing.T) {
	secret := "test-secret-1234567890"

	// Same inputs produce same token
	t1 := computeEscrowToken(secret, "host1")
	t2 := computeEscrowToken(secret, "host1")
	if t1 != t2 {
		t.Error("same inputs should produce same token")
	}

	// Different hostnames produce different tokens
	t3 := computeEscrowToken(secret, "host2")
	if t1 == t3 {
		t.Error("different hostnames should produce different tokens")
	}

	// Different secrets produce different tokens
	t4 := computeEscrowToken("other-secret-1234567890", "host1")
	if t1 == t4 {
		t.Error("different secrets should produce different tokens")
	}
}

func TestHMACWithRotateBreakglassBefore(t *testing.T) {
	secret := "test-secret-1234567890"
	challengeID := "aabbccddee112233aabbccddee112233"
	username := "jordan"
	rotateBefore := "2025-06-01T00:00:00Z"

	srv := &Server{cfg: &Config{SharedSecret: secret}}
	client := NewPAMClient(&Config{SharedSecret: secret}, nil)

	// HMAC with rotateBefore
	token := srv.computeStatusHMAC(challengeID, username, "approved", rotateBefore)
	if !client.verifyStatusToken(challengeID, username, "approved", token, rotateBefore) {
		t.Error("valid token with rotateBefore rejected")
	}

	// Stripping rotateBefore should fail verification (MITM attack)
	if client.verifyStatusToken(challengeID, username, "approved", token, "") {
		t.Error("token computed with rotateBefore should fail when verified without it")
	}

	// Injecting rotateBefore when not present should also fail
	tokenNoRotate := srv.computeStatusHMAC(challengeID, username, "approved", "")
	if client.verifyStatusToken(challengeID, username, "approved", tokenNoRotate, rotateBefore) {
		t.Error("token computed without rotateBefore should fail when verified with it")
	}

	// Token without rotateBefore should verify without it
	if !client.verifyStatusToken(challengeID, username, "approved", tokenNoRotate, "") {
		t.Error("valid token without rotateBefore rejected")
	}
}

func TestConfigBreakglassAbsolutePathRequired(t *testing.T) {
	t.Setenv("PAM_POCKETID_SERVER_URL", "http://localhost:8090")
	t.Setenv("PAM_POCKETID_BREAKGLASS_FILE", "relative/path")

	_, err := LoadClientConfig()
	if err == nil {
		t.Fatal("expected error for relative breakglass file path")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("expected 'absolute path' error, got: %v", err)
	}
}

func TestConfigBreakglassRotationDaysClamp(t *testing.T) {
	t.Setenv("PAM_POCKETID_SERVER_URL", "http://localhost:8090")
	t.Setenv("PAM_POCKETID_BREAKGLASS_ROTATION_DAYS", "99999")

	cfg, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BreakglassRotationDays != 3650 {
		t.Errorf("expected rotation days clamped to 3650, got %d", cfg.BreakglassRotationDays)
	}
}

func TestConfigBreakglassRotationDaysMinimum(t *testing.T) {
	t.Setenv("PAM_POCKETID_SERVER_URL", "http://localhost:8090")
	t.Setenv("PAM_POCKETID_BREAKGLASS_ROTATION_DAYS", "0")

	cfg, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BreakglassRotationDays != 1 {
		t.Errorf("expected rotation days clamped to 1, got %d", cfg.BreakglassRotationDays)
	}
}

func TestConfigBreakglassEnabledDefault(t *testing.T) {
	t.Setenv("PAM_POCKETID_SERVER_URL", "http://localhost:8090")

	cfg, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.BreakglassEnabled {
		t.Error("BreakglassEnabled should default to true")
	}
}

func TestConfigBreakglassEnabledFalse(t *testing.T) {
	t.Setenv("PAM_POCKETID_SERVER_URL", "http://localhost:8090")
	t.Setenv("PAM_POCKETID_BREAKGLASS_ENABLED", "false")

	cfg, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BreakglassEnabled {
		t.Error("BreakglassEnabled should be false when set to 'false'")
	}
}

func TestAuthenticateBreakglass_UnifiedErrorMessages(t *testing.T) {
	origOwnerUID := fileOwnerUID
	fileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	defer func() { fileOwnerUID = origOwnerUID }()

	origOpenTTY := openTTY
	origReadPW := readPasswordFn
	defer func() {
		openTTY = origOpenTTY
		readPasswordFn = origReadPW
	}()

	r, w, _ := os.Pipe()
	w.Close()
	openTTY = func() (*os.File, error) { return r, nil }
	readPasswordFn = func(fd int) ([]byte, error) { return []byte("wrong"), nil }

	origMW := messageWriter
	messageWriter = io.Discard
	defer func() { messageWriter = origMW }()

	dir := t.TempDir()

	// Wrong password path
	hashFile := filepath.Join(dir, "wrongpw")
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	os.WriteFile(hashFile, []byte(string(hash)+"\n"), 0600)

	err1 := authenticateBreakglass("testuser", hashFile)
	if err1 == nil {
		t.Fatal("expected error for wrong password")
	}

	// Nonexistent file path
	err2 := authenticateBreakglass("testuser", filepath.Join(dir, "nonexistent"))
	if err2 == nil {
		t.Fatal("expected error for nonexistent file")
	}

	// Both should return the same generic error message
	if err1.Error() != err2.Error() {
		t.Errorf("error messages should be identical to prevent oracle:\n  wrong password: %q\n  file error:     %q", err1.Error(), err2.Error())
	}
}

func TestEscrowHTTPError_TypedCheck(t *testing.T) {
	err := &escrowHTTPError{StatusCode: 501, Body: "not implemented"}

	var httpErr *escrowHTTPError
	if !errors.As(err, &httpErr) {
		t.Fatal("errors.As should match escrowHTTPError")
	}
	if httpErr.StatusCode != 501 {
		t.Errorf("expected status 501, got %d", httpErr.StatusCode)
	}

	// Wrapped should also match
	wrapped := fmt.Errorf("escrow failed: %w", err)
	if !errors.As(wrapped, &httpErr) {
		t.Fatal("errors.As should match wrapped escrowHTTPError")
	}
}

func TestLastApprovalPruning(t *testing.T) {
	store := NewChallengeStore(2*time.Second, 5*time.Second)
	defer store.Stop()

	// Create and approve a challenge to populate lastApproval
	c, _ := store.Create("pruneuser", "", "")
	store.Approve(c.ID, "pruneuser")

	// Verify the entry exists
	if !store.WithinGracePeriod("pruneuser") {
		t.Fatal("expected user to be within grace period")
	}

	// Wait for the grace period to expire
	time.Sleep(6 * time.Second)

	// Manually trigger reap
	store.reap()

	// The lastApproval entry should be pruned
	store.mu.RLock()
	_, exists := store.lastApproval["pruneuser"]
	store.mu.RUnlock()

	if exists {
		t.Error("stale lastApproval entry should be pruned by reap()")
	}
}
