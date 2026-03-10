package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Pre-parsed templates — avoids re-parsing on every request.
var (
	approvalPageTmpl    = template.Must(template.New("approve").Parse(approvalPageHTML))
	approvalAlreadyTmpl = template.Must(template.New("already").Parse(approvalAlreadyHTML))
)

// Server is the companion auth server that bridges PAM challenges to Pocket ID OIDC.
type Server struct {
	cfg        *Config
	store      *ChallengeStore
	oidcConfig oauth2.Config
	verifier   *oidc.IDTokenVerifier
	mux        *http.ServeMux
}

// validUsername restricts usernames to safe characters, preventing log injection
// and ensuring sane input. Max 64 chars, alphanumeric + dash/underscore/dot.
var validUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// maxRequestBodySize limits the size of incoming request bodies (1KB is plenty for JSON payloads).
const maxRequestBodySize = 1024

// NewServer creates a new auth server.
func NewServer(cfg *Config) (*Server, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discovering OIDC provider: %w", err)
	}

	oidcConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.TrimRight(cfg.ExternalURL, "/") + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	s := &Server{
		cfg:        cfg,
		store:      NewChallengeStore(cfg.ChallengeTTL),
		oidcConfig: oidcConfig,
		verifier:   verifier,
		mux:        http.NewServeMux(),
	}

	s.mux.HandleFunc("/api/challenge", s.handleCreateChallenge)
	s.mux.HandleFunc("/api/challenge/", s.handlePollChallenge)
	s.mux.HandleFunc("/approve/", s.handleApprovalPage)
	s.mux.HandleFunc("/login/", s.handleLogin)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)
	s.mux.HandleFunc("/healthz", s.handleHealthz)

	return s, nil
}

// ServeHTTP implements http.Handler. Adds security headers to all responses.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	s.mux.ServeHTTP(w, r)
}

// verifySharedSecret checks the X-Shared-Secret header using constant-time comparison
// to prevent timing attacks that could leak the secret byte-by-byte.
func (s *Server) verifySharedSecret(r *http.Request) bool {
	if s.cfg.SharedSecret == "" {
		return true
	}
	provided := r.Header.Get("X-Shared-Secret")
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.cfg.SharedSecret), []byte(provided)) == 1
}

// handleCreateChallenge creates a new sudo challenge.
// POST /api/challenge {"username": "jordan"}
func (s *Server) handleCreateChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.verifySharedSecret(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Validate username to prevent log injection and other input-based attacks
	if !validUsername.MatchString(req.Username) {
		http.Error(w, "invalid username format", http.StatusBadRequest)
		return
	}

	challenge, err := s.store.Create(req.Username)
	if err != nil {
		// Rate limit errors are returned by the store when too many challenges exist
		if strings.Contains(err.Error(), "too many") {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		log.Printf("ERROR creating challenge: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	approvalURL := fmt.Sprintf("%s/approve/%s", strings.TrimRight(s.cfg.ExternalURL, "/"), challenge.UserCode)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"challenge_id":     challenge.ID,
		"user_code":        challenge.UserCode,
		"verification_url": approvalURL,
		"expires_in":       int(s.cfg.ChallengeTTL.Seconds()),
	})
}

// handlePollChallenge checks challenge status.
// GET /api/challenge/{id}
func (s *Server) handlePollChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.verifySharedSecret(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/challenge/")
	if id == "" {
		http.Error(w, "challenge ID required", http.StatusBadRequest)
		return
	}

	// Validate challenge ID format (hex string, 32 chars for 16 bytes)
	if len(id) != 32 || !isHex(id) {
		http.Error(w, "invalid challenge ID", http.StatusBadRequest)
		return
	}

	challenge, ok := s.store.Get(id)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"status": string(StatusExpired)})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     challenge.Status,
		"expires_in": int(time.Until(challenge.ExpiresAt).Seconds()),
	})
}

// handleApprovalPage shows the user a page to confirm the sudo request.
// GET /approve/{user_code}
func (s *Server) handleApprovalPage(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/approve/")
	if code == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}

	// Validate user code format to prevent injection (e.g., ABCDEF-123456)
	if len(code) != 13 || code[6] != '-' {
		http.Error(w, "invalid code format", http.StatusBadRequest)
		return
	}

	challenge, ok := s.store.GetByCode(code)
	if !ok {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, approvalExpiredHTML)
		return
	}

	if challenge.Status != StatusPending {
		w.Header().Set("Content-Type", "text/html")
		approvalAlreadyTmpl.Execute(w, map[string]string{
			"Status": string(challenge.Status),
		})
		return
	}

	w.Header().Set("Content-Type", "text/html")
	approvalPageTmpl.Execute(w, map[string]string{
		"Username": challenge.Username,
		"Code":     challenge.UserCode,
		"LoginURL": fmt.Sprintf("%s/login/%s", strings.TrimRight(s.cfg.ExternalURL, "/"), challenge.UserCode),
	})
}

// handleLogin starts the OIDC flow, storing challenge ID in the state parameter.
// GET /login/{user_code}
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	userCode := strings.TrimPrefix(r.URL.Path, "/login/")
	if userCode == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}

	// Validate user code format
	if len(userCode) != 13 || userCode[6] != '-' {
		http.Error(w, "invalid code format", http.StatusBadRequest)
		return
	}

	challenge, ok := s.store.GetByCode(userCode)
	if !ok {
		http.Error(w, "challenge expired or not found", http.StatusNotFound)
		return
	}

	if challenge.Status != StatusPending {
		http.Error(w, "challenge already resolved", http.StatusConflict)
		return
	}

	// Validate that the challenge hasn't expired between GetByCode and now
	if time.Now().After(challenge.ExpiresAt) {
		http.Error(w, "challenge expired", http.StatusNotFound)
		return
	}

	// Generate a cryptographic nonce that:
	// 1. Is stored on the challenge (server-side) to verify on callback
	// 2. Is sent as OIDC nonce claim (verified in the ID token)
	// 3. Is included in the state parameter so we can look it up on callback
	// This prevents CSRF: an attacker cannot forge a valid state without knowing the nonce,
	// and the nonce is bound to this specific challenge server-side.
	nonce, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Store the nonce on the challenge. This also prevents double-login:
	// if someone clicks the login link twice, the second attempt fails because
	// the nonce is already set.
	if err := s.store.SetNonce(challenge.ID, nonce); err != nil {
		// If nonce is already set, the login flow was already initiated.
		// This prevents an attacker from re-initiating the OIDC flow for
		// someone else's challenge.
		http.Error(w, "login already initiated for this challenge", http.StatusConflict)
		return
	}

	// State = challengeID:nonce
	// The challenge ID is safe to include here because:
	// - It travels through the IdP as an opaque state parameter
	// - The nonce portion must match what we stored server-side
	state := challenge.ID + ":" + nonce

	url := s.oidcConfig.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

// oidcExchangeTimeout limits how long we wait for the IdP token exchange.
// Prevents a slow/malicious IdP from holding goroutines indefinitely.
const oidcExchangeTimeout = 15 * time.Second

// handleOIDCCallback processes the OIDC callback after Pocket ID authentication.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// Parse state = challengeID:nonce
	state := r.URL.Query().Get("state")
	parts := strings.SplitN(state, ":", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	challengeID := parts[0]
	stateNonce := parts[1]

	// Validate format of parsed fields
	if len(challengeID) != 32 || !isHex(challengeID) || len(stateNonce) != 32 || !isHex(stateNonce) {
		http.Error(w, "invalid state format", http.StatusBadRequest)
		return
	}

	// Check for error from IdP (sanitize — errParam is attacker-controlled query input)
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		// Only log a safe prefix, strip newlines to prevent log injection
		safeErr := strings.ReplaceAll(errParam, "\n", "")
		safeErr = strings.ReplaceAll(safeErr, "\r", "")
		if len(safeErr) > 64 {
			safeErr = safeErr[:64]
		}
		log.Printf("OIDC error for challenge %s: %s", challengeID[:8], safeErr)
		s.store.Deny(challengeID)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalDeniedHTML)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// Look up the challenge FIRST, before exchanging the code.
	challenge, found := s.store.Get(challengeID)
	if !found {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalExpiredHTML)
		return
	}

	// CRITICAL: Verify the nonce from the state matches what we stored on the challenge.
	if challenge.Nonce == "" {
		// Login was never initiated through our /login/ endpoint
		http.Error(w, "invalid challenge state", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(challenge.Nonce), []byte(stateNonce)) != 1 {
		log.Printf("SECURITY: nonce mismatch for challenge %s — denying", challengeID[:8])
		s.store.Deny(challengeID)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// Exchange code for token with a bounded timeout
	exchangeCtx, cancel := context.WithTimeout(r.Context(), oidcExchangeTimeout)
	defer cancel()

	token, err := s.oidcConfig.Exchange(exchangeCtx, code)
	if err != nil {
		log.Printf("ERROR exchanging code for challenge %s: token exchange failed", challengeID[:8])
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	// Extract and verify ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}

	idToken, err := s.verifier.Verify(exchangeCtx, rawIDToken)
	if err != nil {
		log.Printf("ERROR verifying ID token for challenge %s: verification failed", challengeID[:8])
		http.Error(w, "token verification failed", http.StatusInternalServerError)
		return
	}

	// Verify the OIDC nonce claim matches what we sent.
	if idToken.Nonce != challenge.Nonce {
		log.Printf("SECURITY: OIDC token nonce mismatch for challenge %s — denying", challengeID[:8])
		s.store.Deny(challengeID)
		http.Error(w, "token nonce mismatch", http.StatusBadRequest)
		return
	}

	// Extract claims
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
		Email            string `json:"email"`
		Subject          string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("ERROR parsing claims for challenge %s", challengeID[:8])
		http.Error(w, "failed to parse identity", http.StatusInternalServerError)
		return
	}

	// Verify the authenticated user matches the sudo user.
	// SECURITY: Only match on preferred_username — never on email prefix.
	// Email prefix matching (e.g., "admin@evil.com" matching sudo user "admin")
	// allows cross-domain privilege escalation in multi-tenant IdP setups.
	authenticatedUser := claims.PreferredUsername
	if authenticatedUser == "" {
		log.Printf("DENIED: OIDC token has no preferred_username for challenge %s", challengeID[:8])
		s.store.Deny(challengeID)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalMismatchHTML)
		return
	}

	if !strings.EqualFold(challenge.Username, authenticatedUser) {
		log.Printf("DENIED: authenticated identity does not match challenge user for challenge %s", challengeID[:8])
		s.store.Deny(challengeID)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalMismatchHTML)
		return
	}

	// Approve the challenge
	if err := s.store.Approve(challengeID, authenticatedUser); err != nil {
		log.Printf("ERROR approving challenge %s", challengeID[:8])
		http.Error(w, "failed to approve", http.StatusInternalServerError)
		return
	}

	log.Printf("APPROVED: sudo for user %q (challenge %s)", challenge.Username, challengeID[:8])
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, approvalSuccessHTML)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// isHex returns true if s contains only hexadecimal characters.
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// HTML templates
// All user-controlled values are rendered via html/template (auto-escaped).

const approvalPageHTML = `<!DOCTYPE html>
<html>
<head>
  <title>Sudo Approval</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; text-align: center; background: #f5f5f5; }
    .card { background: white; border-radius: 12px; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .code { font-size: 2em; font-weight: bold; letter-spacing: 0.15em; color: #333; margin: 20px 0; font-family: monospace; }
    .user { color: #d63031; font-weight: bold; }
    .btn { display: inline-block; background: #0984e3; color: white; padding: 14px 40px; border-radius: 8px; text-decoration: none; font-size: 1.1em; margin-top: 20px; }
    .btn:hover { background: #0874c9; }
    .warn { color: #636e72; font-size: 0.9em; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Sudo Elevation Request</h2>
    <p>User <span class="user">{{.Username}}</span> is requesting sudo access.</p>
    <div class="code">{{.Code}}</div>
    <p>If this was you, sign in to approve:</p>
    <a href="{{.LoginURL}}" class="btn">Authenticate with Pocket ID</a>
    <p class="warn">If you did not request this, close this page.</p>
  </div>
</body>
</html>`

const approvalSuccessHTML = `<!DOCTYPE html>
<html>
<head><title>Approved</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;text-align:center;background:#f5f5f5}.card{background:white;border-radius:12px;padding:40px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}.ok{font-size:3em;margin-bottom:10px}</style>
</head>
<body><div class="card"><div class="ok">&#10003;</div><h2>Sudo Approved</h2><p>You can close this window. Your terminal session will continue.</p></div></body>
</html>`

const approvalDeniedHTML = `<!DOCTYPE html>
<html>
<head><title>Denied</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;text-align:center;background:#f5f5f5}.card{background:white;border-radius:12px;padding:40px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}.err{font-size:3em;margin-bottom:10px;color:#d63031}</style>
</head>
<body><div class="card"><div class="err">&#10007;</div><h2>Authentication Failed</h2><p>The sudo request was denied.</p></div></body>
</html>`

const approvalMismatchHTML = `<!DOCTYPE html>
<html>
<head><title>Identity Mismatch</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;text-align:center;background:#f5f5f5}.card{background:white;border-radius:12px;padding:40px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}.err{font-size:3em;margin-bottom:10px;color:#d63031}</style>
</head>
<body><div class="card"><div class="err">&#10007;</div><h2>Identity Mismatch</h2><p>The authenticated identity does not match the user requesting sudo. You must authenticate as the same user.</p></div></body>
</html>`

const approvalExpiredHTML = `<!DOCTYPE html>
<html>
<head><title>Expired</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;text-align:center;background:#f5f5f5}.card{background:white;border-radius:12px;padding:40px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}</style>
</head>
<body><div class="card"><h2>Challenge Expired</h2><p>This sudo approval request has expired or does not exist. Run your sudo command again.</p></div></body>
</html>`

// approvalAlreadyHTML uses html/template syntax so the status is safely escaped.
const approvalAlreadyHTML = `<!DOCTYPE html>
<html>
<head><title>Already Resolved</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;text-align:center;background:#f5f5f5}.card{background:white;border-radius:12px;padding:40px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}</style>
</head>
<body><div class="card"><h2>Already Resolved</h2><p>This sudo request has already been {{.Status}}.</p></div></body>
</html>`
