package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

// validHostname restricts hostnames to RFC 1035 characters, preventing log injection.
// Max 253 chars, alphanumeric + hyphens + dots.
var validHostname = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,253}$`)

// maxRequestBodySize limits the size of incoming request bodies (1KB is plenty for JSON payloads).
const maxRequestBodySize = 1024

// oidcDiscoveryTimeout limits how long we wait for OIDC provider discovery at startup.
const oidcDiscoveryTimeout = 30 * time.Second

// NewServer creates a new auth server.
func NewServer(cfg *Config) (*Server, error) {
	// Use a hardened HTTP client for OIDC discovery to prevent SSRF via redirects
	// and OOM via unbounded response bodies. Matches the pattern used for token exchange.
	discoveryClient := &http.Client{
		Timeout: oidcDiscoveryTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, discoveryClient)

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
		store:      NewChallengeStore(cfg.ChallengeTTL, cfg.GracePeriod),
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
	s.mux.Handle("/metrics", promhttp.Handler())

	return s, nil
}

// Stop cleanly shuts down the server's background resources.
func (s *Server) Stop() {
	s.store.Stop()
}

// ServeHTTP implements http.Handler. Adds security headers and panic recovery.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rv := recover(); rv != nil {
			log.Printf("ERROR: panic in handler from %s: %v", remoteAddr(r), rv)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if s.cfg.ExternalURL != "" && strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
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
	// Hash both values before comparison to prevent length leakage.
	// subtle.ConstantTimeCompare returns 0 immediately for different-length
	// inputs, which would leak the secret's length via timing.
	expectedHash := sha256.Sum256([]byte(s.cfg.SharedSecret))
	providedHash := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}

// remoteAddr extracts the client IP from a request for logging.
func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleCreateChallenge creates a new sudo challenge.
// POST /api/challenge {"username": "jordan"}
func (s *Server) handleCreateChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.verifySharedSecret(r) {
		authFailures.Inc()
		log.Printf("AUTH_FAILURE: invalid shared secret from %s on POST /api/challenge", remoteAddr(r))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify Content-Type to prevent cross-origin form submission
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Username string `json:"username"`
		Hostname string `json:"hostname"`
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

	// Validate hostname to prevent log injection (hostname is optional, empty is OK)
	if req.Hostname != "" && !validHostname.MatchString(req.Hostname) {
		http.Error(w, "invalid hostname format", http.StatusBadRequest)
		return
	}

	challenge, err := s.store.Create(req.Username, req.Hostname)
	if err != nil {
		// Rate limit errors are returned by the store when too many challenges exist
		if strings.Contains(err.Error(), "too many") {
			rateLimitRejections.Inc()
			log.Printf("RATE_LIMIT: user %q from %s (host %q)", req.Username, remoteAddr(r), req.Hostname)
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		log.Printf("ERROR creating challenge: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	challengesCreated.WithLabelValues(req.Username).Inc()
	activeChallenges.Inc()
	log.Printf("CHALLENGE: created %s for user %q from %s (host %q)", challenge.ID[:8], req.Username, remoteAddr(r), req.Hostname)

	// Auto-approve if within grace period
	if s.store.WithinGracePeriod(req.Username) {
		if err := s.store.AutoApprove(challenge.ID); err == nil {
			challengesAutoApproved.Inc()
			activeChallenges.Dec()
			challengeDuration.Observe(0)
			log.Printf("GRACE: auto-approved sudo for user %q (challenge %s) — recent authentication within grace period", req.Username, challenge.ID[:8])

			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"challenge_id": challenge.ID,
				"user_code":    challenge.UserCode,
				"expires_in":   int(s.cfg.ChallengeTTL.Seconds()),
				"status":       "approved",
			}
			if s.cfg.SharedSecret != "" {
				resp["approval_token"] = s.computeStatusHMAC(challenge.ID, req.Username, "approved")
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
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
		authFailures.Inc()
		log.Printf("AUTH_FAILURE: invalid shared secret from %s on GET /api/challenge/", remoteAddr(r))
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

	resp := map[string]interface{}{
		"status":     challenge.Status,
		"expires_in": int(time.Until(challenge.ExpiresAt).Seconds()),
	}
	// Include HMAC status tokens so the PAM client can verify the response
	// is genuine and not injected by a MITM
	if s.cfg.SharedSecret != "" {
		switch challenge.Status {
		case StatusApproved:
			resp["approval_token"] = s.computeStatusHMAC(id, challenge.Username, "approved")
		case StatusDenied:
			resp["denial_token"] = s.computeStatusHMAC(id, challenge.Username, "denied")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleApprovalPage shows the user a page to confirm the sudo request.
// GET /approve/{user_code}
func (s *Server) handleApprovalPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	log.Printf("ACCESS: GET /approve/ from %s (code=%s...)", remoteAddr(r), code[:6])

	challenge, ok := s.store.GetByCode(code)
	if !ok {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, approvalExpiredHTML)
		return
	}

	if challenge.Status != StatusPending {
		w.Header().Set("Content-Type", "text/html")
		if err := approvalAlreadyTmpl.Execute(w, map[string]string{
			"Status": string(challenge.Status),
		}); err != nil {
			log.Printf("ERROR: template execution: %v", err)
		}
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := approvalPageTmpl.Execute(w, map[string]string{
		"Username": challenge.Username,
		"Code":     challenge.UserCode,
		"LoginURL": fmt.Sprintf("%s/login/%s", strings.TrimRight(s.cfg.ExternalURL, "/"), challenge.UserCode),
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

// handleLogin starts the OIDC flow, storing challenge ID in the state parameter.
// GET /login/{user_code}
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	log.Printf("ACCESS: GET /login/ from %s (code=%s...)", remoteAddr(r), userCode[:6])

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
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse state = challengeID:nonce
	state := r.URL.Query().Get("state")
	parts := strings.SplitN(state, ":", 2)
	if len(parts) != 2 {
		log.Printf("SECURITY: invalid state parameter (no colon) from %s", remoteAddr(r))
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	challengeID := parts[0]
	stateNonce := parts[1]

	// Validate format of parsed fields
	if len(challengeID) != 32 || !isHex(challengeID) || len(stateNonce) != 32 || !isHex(stateNonce) {
		log.Printf("SECURITY: malformed state format from %s", remoteAddr(r))
		http.Error(w, "invalid state format", http.StatusBadRequest)
		return
	}

	// Look up the challenge FIRST, before processing any parameters.
	challenge, found := s.store.Get(challengeID)
	if !found {
		log.Printf("SECURITY: callback for unknown/expired challenge %s from %s", challengeID[:8], remoteAddr(r))
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalExpiredHTML)
		return
	}

	// CRITICAL: Verify the nonce from the state matches what we stored on the challenge.
	// This MUST happen before acting on any other parameters (error, code) to prevent
	// an attacker from denying challenges by forging callbacks with error= parameters.
	if challenge.Nonce == "" {
		// Login was never initiated through our /login/ endpoint
		log.Printf("SECURITY: callback for challenge %s with no nonce set (login never initiated) from %s", challengeID[:8], remoteAddr(r))
		http.Error(w, "invalid challenge state", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(challenge.Nonce), []byte(stateNonce)) != 1 {
		log.Printf("SECURITY: nonce mismatch for challenge %s from %s — possible forged callback", challengeID[:8], remoteAddr(r))
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// Check for error from IdP (sanitize — errParam is attacker-controlled query input).
	// Safe to act on now that the nonce has been verified.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		// Strip all control characters (newlines, ANSI escapes, null bytes) to prevent log injection
		safeErr := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, errParam)
		if len(safeErr) > 64 {
			safeErr = safeErr[:64]
		}
		challengesDenied.WithLabelValues("oidc_error").Inc()
		activeChallenges.Dec()
		challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
		log.Printf("OIDC error for challenge %s from %s: %s", challengeID[:8], remoteAddr(r), safeErr)
		s.store.Deny(challengeID)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalDeniedHTML)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		log.Printf("SECURITY: callback with missing authorization code from %s (challenge %s)", remoteAddr(r), challengeID[:8])
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for token with a bounded timeout.
	// Use a hardened HTTP client: disable redirect following to prevent the
	// authorization code from being forwarded if the IdP's token endpoint
	// redirects to an attacker-controlled server.
	exchangeCtx, cancel := context.WithTimeout(r.Context(), oidcExchangeTimeout)
	defer cancel()
	exchangeClient := &http.Client{
		Timeout: oidcExchangeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	exchangeCtx = context.WithValue(exchangeCtx, oauth2.HTTPClient, exchangeClient)

	token, err := s.oidcConfig.Exchange(exchangeCtx, code)
	if err != nil {
		log.Printf("ERROR exchanging code for challenge %s from %s: token exchange failed", challengeID[:8], remoteAddr(r))
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	// Extract and verify ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Printf("ERROR: no id_token in token response for challenge %s from %s", challengeID[:8], remoteAddr(r))
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}

	idToken, err := s.verifier.Verify(exchangeCtx, rawIDToken)
	if err != nil {
		log.Printf("ERROR verifying ID token for challenge %s from %s: verification failed", challengeID[:8], remoteAddr(r))
		http.Error(w, "token verification failed", http.StatusInternalServerError)
		return
	}

	// Verify the OIDC nonce claim matches what we sent (constant-time comparison).
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(challenge.Nonce)) != 1 {
		challengesDenied.WithLabelValues("nonce_mismatch").Inc()
		activeChallenges.Dec()
		challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
		log.Printf("SECURITY: OIDC token nonce mismatch for challenge %s from %s — denying", challengeID[:8], remoteAddr(r))
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
		log.Printf("ERROR parsing claims for challenge %s from %s", challengeID[:8], remoteAddr(r))
		http.Error(w, "failed to parse identity", http.StatusInternalServerError)
		return
	}

	// Verify the authenticated user matches the sudo user.
	// SECURITY: Only match on preferred_username — never on email prefix.
	// Email prefix matching (e.g., "admin@evil.com" matching sudo user "admin")
	// allows cross-domain privilege escalation in multi-tenant IdP setups.
	authenticatedUser := claims.PreferredUsername
	if authenticatedUser == "" {
		challengesDenied.WithLabelValues("identity_mismatch").Inc()
		activeChallenges.Dec()
		challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
		log.Printf("DENIED: OIDC token has no preferred_username for challenge %s from %s", challengeID[:8], remoteAddr(r))
		s.store.Deny(challengeID)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalMismatchHTML)
		return
	}
	// Validate the IdP-provided username format to prevent log injection
	// and catch IdP misconfigurations (e.g., email as preferred_username).
	if !validUsername.MatchString(authenticatedUser) {
		challengesDenied.WithLabelValues("identity_mismatch").Inc()
		activeChallenges.Dec()
		challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
		log.Printf("DENIED: OIDC preferred_username %q fails validation for challenge %s from %s", authenticatedUser, challengeID[:8], remoteAddr(r))
		s.store.Deny(challengeID)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalMismatchHTML)
		return
	}

	if challenge.Username != authenticatedUser {
		challengesDenied.WithLabelValues("identity_mismatch").Inc()
		activeChallenges.Dec()
		challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
		log.Printf("DENIED: user %q authenticated but challenge %s is for %q (host %q) from %s", authenticatedUser, challengeID[:8], challenge.Username, challenge.Hostname, remoteAddr(r))
		s.store.Deny(challengeID)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, approvalMismatchHTML)
		return
	}

	// Approve the challenge
	if err := s.store.Approve(challengeID, authenticatedUser); err != nil {
		log.Printf("ERROR approving challenge %s from %s", challengeID[:8], remoteAddr(r))
		http.Error(w, "failed to approve", http.StatusInternalServerError)
		return
	}

	challengesApproved.Inc()
	activeChallenges.Dec()
	challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
	log.Printf("APPROVED: sudo for user %q on host %q (challenge %s) from %s", challenge.Username, challenge.Hostname, challengeID[:8], remoteAddr(r))
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, approvalSuccessHTML)
}

// computeStatusHMAC creates an HMAC-SHA256 token binding a challenge status
// to the specific challengeID, username, and status string, preventing
// poll response forgery by MITM for both approvals and denials.
// Uses length-prefixed fields instead of delimiter-separated to prevent
// field injection (e.g., a username containing ":" could shift field boundaries
// in a colon-delimited format).
func (s *Server) computeStatusHMAC(challengeID, username, status string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(challengeID), challengeID, len(status), status, len(username), username)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// isHex returns true if s is non-empty and contains only hexadecimal characters.
func isHex(s string) bool {
	if s == "" {
		return false
	}
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
