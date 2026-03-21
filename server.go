package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
)

// Pre-parsed templates — avoids re-parsing on every request.
var (
	approvalPageTmpl     = template.Must(template.New("approve").Parse(approvalPageHTML))
	approvalAlreadyTmpl  = template.Must(template.New("already").Parse(approvalAlreadyHTML))
	approvalMismatchTmpl = template.Must(template.New("mismatch").Parse(approvalMismatchHTML))
	approvalSuccessTmpl  = template.Must(template.New("success").Funcs(template.FuncMap{
		"formatDuration": formatDuration,
	}).Parse(approvalSuccessHTML))
	sessionsListTmpl = template.Must(template.New("sessionsList").Funcs(template.FuncMap{
		"formatDuration": formatDuration,
	}).Parse(sessionsListHTML))
)

// escrowTimeout limits how long we wait for the escrow command to complete.
const escrowTimeout = 30 * time.Second

// escrowMaxOutput caps the amount of stdout/stderr we read from the escrow
// command to prevent memory exhaustion from a verbose or malicious command.
const escrowMaxOutput = 1 << 20 // 1 MB

// escrowSemaphore limits concurrent escrow command executions to prevent
// resource exhaustion from an attacker flooding the endpoint.
var escrowSemaphore = make(chan struct{}, 5)

// Server is the companion auth server that bridges PAM challenges to Pocket ID OIDC.
type Server struct {
	cfg            *Config
	store          *ChallengeStore
	oidcConfig     oauth2.Config
	verifier       *oidc.IDTokenVerifier
	mux            *http.ServeMux
	notifyWg       sync.WaitGroup // tracks in-flight notification goroutines for graceful shutdown
	sessionNonces  map[string]time.Time // nonce -> creation time for /sessions OIDC flow
	sessionNonceMu sync.Mutex
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
		cfg:           cfg,
		store:         NewChallengeStore(cfg.ChallengeTTL, cfg.GracePeriod, cfg.SessionStateFile),
		oidcConfig:    oidcConfig,
		verifier:      verifier,
		mux:           http.NewServeMux(),
		sessionNonces: make(map[string]time.Time),
	}

	s.mux.HandleFunc("/api/challenge", s.handleCreateChallenge)
	s.mux.HandleFunc("/api/challenge/", s.handlePollChallenge)
	s.mux.HandleFunc("/api/grace-status", s.handleGraceStatus)
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)
	s.mux.HandleFunc("/api/sessions/revoke", s.handleRevokeSession)
	s.mux.HandleFunc("/approve/", s.handleApprovalPage)
	s.mux.HandleFunc("/login/", s.handleLogin)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)
	s.mux.HandleFunc("/sessions", s.handleSessionsPage)
	s.mux.HandleFunc("/sessions/login", s.handleSessionsLogin)
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

	// Snapshot the rotation signal BEFORE creating the challenge so the value
	// is set on the struct before it enters the store's map (avoids data race
	// with concurrent Get() calls that copy the struct under RLock).
	var rotateBefore string
	if !s.cfg.BreakglassRotateBefore.IsZero() {
		rotateBefore = s.cfg.BreakglassRotateBefore.Format(time.RFC3339)
	}

	challenge, err := s.store.Create(req.Username, req.Hostname, rotateBefore)
	if err != nil {
		// Rate limit errors are returned by the store when too many challenges exist
		if errors.Is(err, ErrTooManyChallenges) || errors.Is(err, ErrTooManyPerUser) {
			rateLimitRejections.Inc()
			log.Printf("RATE_LIMIT: user %q from %s (host %q)", req.Username, remoteAddr(r), req.Hostname)
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		log.Printf("ERROR creating challenge: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	challengesCreated.Inc()
	activeChallenges.Inc()
	log.Printf("CHALLENGE: created %s for user %q from %s (host %q)", challenge.ID[:8], req.Username, remoteAddr(r), req.Hostname)

	// Build client_config if any server-side client overrides are set
	clientCfg := s.buildClientConfig()

	// Auto-approve if within grace period
	if s.store.WithinGracePeriod(req.Username, req.Hostname) {
		if err := s.store.AutoApprove(challenge.ID); err == nil {
			challengesAutoApproved.Inc()
			activeChallenges.Dec()
			challengeDuration.Observe(0)
			log.Printf("GRACE: auto-approved sudo for user %q (challenge %s) — recent authentication within grace period", req.Username, challenge.ID[:8])

			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"challenge_id":    challenge.ID,
				"user_code":       challenge.UserCode,
				"expires_in":      int(s.cfg.ChallengeTTL.Seconds()),
				"status":          "approved",
				"grace_remaining": int(s.store.GraceRemaining(req.Username, req.Hostname).Seconds()),
			}
			if s.cfg.SharedSecret != "" {
				resp["approval_token"] = s.computeStatusHMAC(challenge.ID, req.Username, "approved", challenge.BreakglassRotateBefore, challenge.RevokeTokensBefore)
			}
			if challenge.BreakglassRotateBefore != "" {
				resp["rotate_breakglass_before"] = challenge.BreakglassRotateBefore
			}
			if challenge.RevokeTokensBefore != "" {
				resp["revoke_tokens_before"] = challenge.RevokeTokensBefore
			}
			if clientCfg != nil {
				resp["client_config"] = clientCfg
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	approvalURL := fmt.Sprintf("%s/approve/%s", strings.TrimRight(s.cfg.ExternalURL, "/"), challenge.UserCode)

	// Fire push notification asynchronously (no-op if not configured).
	s.sendNotification(challenge, approvalURL)

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"challenge_id":     challenge.ID,
		"user_code":        challenge.UserCode,
		"verification_url": approvalURL,
		"expires_in":       int(s.cfg.ChallengeTTL.Seconds()),
	}
	if s.cfg.NotifyCommand != "" {
		// Only indicate notification_sent if the notification is likely to
		// reach someone: either no per-user file is configured (global command),
		// or the user has a mapping (including wildcard).
		if s.cfg.NotifyUsersFile == "" {
			resp["notification_sent"] = true
		} else if urls := lookupUserURLs(loadNotifyUsers(s.cfg.NotifyUsersFile), req.Username); urls != "" {
			resp["notification_sent"] = true
		}
	}
	if challenge.BreakglassRotateBefore != "" {
		resp["rotate_breakglass_before"] = challenge.BreakglassRotateBefore
	}
	if challenge.RevokeTokensBefore != "" {
		resp["revoke_tokens_before"] = challenge.RevokeTokensBefore
	}
	if clientCfg != nil {
		resp["client_config"] = clientCfg
	}
	json.NewEncoder(w).Encode(resp)
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
			resp["approval_token"] = s.computeStatusHMAC(id, challenge.Username, "approved", challenge.BreakglassRotateBefore, challenge.RevokeTokensBefore)
			// Forward the raw ID token so the PAM client can cache it locally
			// for subsequent authentication without a full device flow.
			if challenge.RawIDToken != "" {
				resp["id_token"] = challenge.RawIDToken
			}
			// Include grace period remaining so the client can show the
			// effective re-auth window (max of token expiry and grace period).
			if gr := s.store.GraceRemaining(challenge.Username, challenge.Hostname); gr > 0 {
				resp["grace_remaining"] = int(gr.Seconds())
			}
		case StatusDenied:
			resp["denial_token"] = s.computeStatusHMAC(id, challenge.Username, "denied", challenge.BreakglassRotateBefore, challenge.RevokeTokensBefore)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleGraceStatus returns the grace period remaining for a user@host.
// GET /api/grace-status?username=X&hostname=Y
// Used by the PAM client to get the accurate grace time on cache hits.
func (s *Server) handleGraceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifySharedSecret(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	username := r.URL.Query().Get("username")
	hostname := r.URL.Query().Get("hostname")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	remaining := s.store.GraceRemaining(username, hostname)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"grace_remaining": int(remaining.Seconds()),
	})
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
		status := string(challenge.Status)
		if len(status) > 0 {
			status = strings.ToUpper(status[:1]) + status[1:]
		}
		if err := approvalAlreadyTmpl.Execute(w, map[string]string{
			"Status": status,
		}); err != nil {
			log.Printf("ERROR: template execution: %v", err)
		}
		return
	}

	// Build duration options for the approval page.
	// Show preset options that fit within the server's max grace period.
	// If no presets fit (grace < 1h), show just the server's max as the only option.
	type durOption struct {
		Label   string
		Seconds int
		Active  bool
	}
	allDurations := []durOption{
		{"1h", 3600, false},
		{"4h", 14400, false},
		{"8h", 28800, false},
		{"1d", 86400, false},
	}
	var durations []durOption
	maxSec := int(s.cfg.GracePeriod.Seconds())
	for _, d := range allDurations {
		if d.Seconds <= maxSec {
			durations = append(durations, d)
		}
	}
	// If no preset fits (grace < 1h), add the server's actual max as the only option
	if len(durations) == 0 && maxSec > 0 {
		label := fmt.Sprintf("%dm", maxSec/60)
		if maxSec < 60 {
			label = fmt.Sprintf("%ds", maxSec)
		}
		durations = append(durations, durOption{label, maxSec, true})
	}
	// Mark the default as active (the largest available option)
	if len(durations) > 0 && !durations[len(durations)-1].Active {
		durations[len(durations)-1].Active = true
	}

	loginURL := fmt.Sprintf("%s/login/%s", strings.TrimRight(s.cfg.ExternalURL, "/"), challenge.UserCode)

	w.Header().Set("Content-Type", "text/html")
	if err := approvalPageTmpl.Execute(w, map[string]interface{}{
		"Username":      challenge.Username,
		"Hostname":      challenge.Hostname,
		"Code":          challenge.UserCode,
		"LoginURL":      loginURL,
		"Durations":     durations,
		"HasGrace":      s.cfg.GracePeriod > 0,
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

	// Parse optional duration parameter (seconds) from approval page buttons.
	// Clamp to [min(1h, GracePeriod), GracePeriod] — the floor must never
	// exceed the server's configured max.
	if durStr := r.URL.Query().Get("duration"); durStr != "" {
		if durSec, err := strconv.Atoi(durStr); err == nil {
			dur := time.Duration(durSec) * time.Second
			if s.cfg.GracePeriod > 0 {
				floor := 1 * time.Hour
				if floor > s.cfg.GracePeriod {
					floor = s.cfg.GracePeriod
				}
				if dur < floor {
					dur = floor
				}
				if dur > s.cfg.GracePeriod {
					dur = s.cfg.GracePeriod
				}
				s.store.SetRequestedGrace(challenge.ID, dur)
			}
		}
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

	// Parse state parameter. Two formats:
	// 1. "sessions:<nonce>" — callback for /sessions page OIDC flow
	// 2. "<challengeID>:<nonce>" — callback for approval OIDC flow
	state := r.URL.Query().Get("state")

	// Handle sessions callback
	if strings.HasPrefix(state, "sessions:") {
		s.handleSessionsCallback(w, r)
		return
	}

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
		if err := approvalMismatchTmpl.Execute(w, map[string]string{
			"AuthenticatedUser": "(unknown)",
			"ExpectedUser":      challenge.Username,
		}); err != nil {
			log.Printf("ERROR: template execution: %v", err)
		}
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
		if err := approvalMismatchTmpl.Execute(w, map[string]string{
			"AuthenticatedUser": "(invalid)",
			"ExpectedUser":      challenge.Username,
		}); err != nil {
			log.Printf("ERROR: template execution: %v", err)
		}
		return
	}

	if challenge.Username != authenticatedUser {
		challengesDenied.WithLabelValues("identity_mismatch").Inc()
		activeChallenges.Dec()
		challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
		log.Printf("DENIED: user %q authenticated but challenge %s is for %q (host %q) from %s", authenticatedUser, challengeID[:8], challenge.Username, challenge.Hostname, remoteAddr(r))
		s.store.Deny(challengeID)
		w.Header().Set("Content-Type", "text/html")
		if err := approvalMismatchTmpl.Execute(w, map[string]string{
			"AuthenticatedUser": authenticatedUser,
			"ExpectedUser":      challenge.Username,
		}); err != nil {
			log.Printf("ERROR: template execution: %v", err)
		}
		return
	}

	// Approve the challenge
	if err := s.store.Approve(challengeID, authenticatedUser); err != nil {
		log.Printf("ERROR approving challenge %s from %s", challengeID[:8], remoteAddr(r))
		http.Error(w, "failed to approve", http.StatusInternalServerError)
		return
	}

	// Store the raw ID token on the challenge for forwarding to the PAM client cache.
	s.store.SetIDToken(challengeID, rawIDToken)

	challengesApproved.Inc()
	activeChallenges.Dec()
	challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
	log.Printf("APPROVED: sudo for user %q on host %q (challenge %s) from %s", challenge.Username, challenge.Hostname, challengeID[:8], remoteAddr(r))

	// Build session list and CSRF tokens for the success page
	sessions := s.store.ActiveSessions(challenge.Username)
	type sessionView struct {
		Hostname  string
		Remaining string
		CSRFToken string
		CSRFTs    string
	}
	var sessionViews []sessionView
	now := time.Now()
	csrfTs := fmt.Sprintf("%d", now.Unix())
	for _, sess := range sessions {
		csrfToken := computeCSRFToken(s.cfg.SharedSecret, challenge.Username, csrfTs)
		sessionViews = append(sessionViews, sessionView{
			Hostname:  sess.Hostname,
			Remaining: formatDuration(time.Until(sess.ExpiresAt)),
			CSRFToken: csrfToken,
			CSRFTs:    csrfTs,
		})
	}

	w.Header().Set("Content-Type", "text/html")
	if err := approvalSuccessTmpl.Execute(w, map[string]interface{}{
		"Username": challenge.Username,
		"Sessions": sessionViews,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

// computeStatusHMAC creates an HMAC-SHA256 token binding a challenge status to the
// specific challengeID, username, status, rotateBefore, and revokeTokensBefore.
// Uses length-prefixed fields to prevent field injection.
// The rotateBefore and revokeTokensBefore parameters are the per-challenge snapshots
// stored at challenge creation, ensuring HMAC consistency even if the server config
// changes between creation and poll. Empty optional fields are omitted for
// backward compatibility.
func (s *Server) computeStatusHMAC(challengeID, username, status, rotateBefore, revokeTokensBefore string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(challengeID), challengeID, len(status), status, len(username), username)
	// Include rotate_breakglass_before in the HMAC so a MITM cannot inject
	// a rotation signal without invalidating the token.
	if rotateBefore != "" {
		fmt.Fprintf(mac, "%d:%s", len(rotateBefore), rotateBefore)
	}
	// Include revoke_tokens_before in the HMAC so a MITM cannot inject
	// a revocation signal without invalidating the token.
	if revokeTokensBefore != "" {
		fmt.Fprintf(mac, "r%d:%s", len(revokeTokensBefore), revokeTokensBefore)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// computeCSRFToken creates an HMAC-SHA256 CSRF token for session revocation forms.
// Format: HMAC(shared_secret, username + ":" + timestamp)
func computeCSRFToken(sharedSecret, username, timestamp string) string {
	if sharedSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write([]byte(username + ":" + timestamp))
	return hex.EncodeToString(mac.Sum(nil))
}

// revokeErrorPage renders a styled error page for revoke failures.
func revokeErrorPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	io.WriteString(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <title>`+template.HTMLEscapeString(title)+`</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>`+sharedCSS+`
    .icon-warning { background: var(--warning-bg); border: 2px solid var(--warning-border); color: var(--warning); }
    h2 { color: var(--warning); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-warning" aria-hidden="true">&#x26a0;</div>
    <h2>`+template.HTMLEscapeString(title)+`</h2>
    <p>`+template.HTMLEscapeString(message)+`</p>
  </div>
</body>
</html>`)
}

// handleRevokeSession processes session revocation from the success page.
// POST /api/sessions/revoke
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		revokeErrorPage(w, http.StatusBadRequest, "Invalid request", "The form submission was invalid.")
		return
	}

	hostname := r.FormValue("hostname")
	csrfToken := r.FormValue("csrf_token")
	csrfTs := r.FormValue("csrf_ts")
	username := r.FormValue("username")

	if hostname == "" || csrfToken == "" || csrfTs == "" || username == "" {
		revokeErrorPage(w, http.StatusBadRequest, "Invalid request", "Required fields are missing.")
		return
	}

	// Validate username and hostname formats
	if !validUsername.MatchString(username) || !validHostname.MatchString(hostname) {
		revokeErrorPage(w, http.StatusBadRequest, "Invalid request", "The username or hostname format is invalid.")
		return
	}

	// Verify CSRF timestamp is within 5 minutes
	tsInt, err := strconv.ParseInt(csrfTs, 10, 64)
	if err != nil {
		revokeErrorPage(w, http.StatusBadRequest, "Invalid request", "The request timestamp is invalid.")
		return
	}
	tsTime := time.Unix(tsInt, 0)
	if time.Since(tsTime).Abs() > 5*time.Minute {
		revokeErrorPage(w, http.StatusForbidden, "Session expired", "This page has expired. Please approve a new sudo request to manage your sessions.")
		return
	}

	// Verify CSRF token
	expected := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) != 1 {
		revokeErrorPage(w, http.StatusForbidden, "Invalid request", "The security token is invalid. Please approve a new sudo request to manage your sessions.")
		return
	}

	s.store.RevokeSession(username, hostname)
	log.Printf("SESSION_REVOKED: user %q host %q from %s", username, hostname, remoteAddr(r))

	// Render a simple confirmation page
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Session revoked</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>`+sharedCSS+`
    .icon-success {
      background: var(--success-bg);
      border: 2px solid var(--success-border);
      color: var(--success);
    }
    h2 { color: var(--success); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-success" aria-hidden="true">&#x2713;</div>
    <h2>Session revoked</h2>
    <p>The session for <strong>`+template.HTMLEscapeString(username)+`</strong> on <strong>`+template.HTMLEscapeString(hostname)+`</strong> has been revoked.</p>
  </div>
</body>
</html>`)
}

// cleanExpiredSessionNonces removes expired nonces (>5 min) from the map.
// Must be called under sessionNonceMu lock.
func (s *Server) cleanExpiredSessionNonces() {
	cutoff := time.Now().Add(-5 * time.Minute)
	for nonce, created := range s.sessionNonces {
		if created.Before(cutoff) {
			delete(s.sessionNonces, nonce)
		}
	}
}

// handleSessionsPage renders a landing page with a sign-in button.
// GET /sessions
func (s *Server) handleSessionsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	loginURL := strings.TrimRight(s.cfg.ExternalURL, "/") + "/sessions/login"
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Manage sessions</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>`+sharedCSS+`
    .icon-info {
      background: var(--info-bg);
      border: 2px solid var(--info-border);
      color: var(--primary);
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: var(--primary);
      color: var(--primary-text);
      padding: 12px 32px;
      border-radius: 10px;
      text-decoration: none;
      font-size: 0.938rem;
      font-weight: 600;
      border: none;
      cursor: pointer;
      transition: background 0.15s ease, box-shadow 0.15s ease, transform 0.1s ease;
      width: 100%;
      max-width: 320px;
      margin-top: 16px;
    }
    .btn:hover { background: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.3); }
    .btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
    .btn:active { transform: translateY(0); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-info" aria-hidden="true">&#x1f511;</div>
    <h2>Manage sessions</h2>
    <p>Sign in with Pocket ID to view and revoke your active sudo sessions.</p>
    <a href="`+template.HTMLEscapeString(loginURL)+`" class="btn" role="button">Sign in to manage sessions</a>
  </div>
</body>
</html>`)
}

// handleSessionsLogin initiates an OIDC flow for the sessions management page.
// GET /sessions/login
func (s *Server) handleSessionsLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nonce, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.sessionNonceMu.Lock()
	s.cleanExpiredSessionNonces()
	s.sessionNonces[nonce] = time.Now()
	s.sessionNonceMu.Unlock()

	state := "sessions:" + nonce
	url := s.oidcConfig.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

// handleSessionsCallback processes the OIDC callback for the sessions management page.
// Called from handleOIDCCallback when state starts with "sessions:".
func (s *Server) handleSessionsCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	stateNonce := strings.TrimPrefix(state, "sessions:")

	// Validate nonce format
	if len(stateNonce) != 32 || !isHex(stateNonce) {
		log.Printf("SECURITY: malformed sessions state from %s", remoteAddr(r))
		http.Error(w, "invalid state format", http.StatusBadRequest)
		return
	}

	// Verify and consume the nonce
	s.sessionNonceMu.Lock()
	s.cleanExpiredSessionNonces()
	_, nonceValid := s.sessionNonces[stateNonce]
	if nonceValid {
		delete(s.sessionNonces, stateNonce)
	}
	s.sessionNonceMu.Unlock()

	if !nonceValid {
		log.Printf("SECURITY: unknown or expired sessions nonce from %s", remoteAddr(r))
		http.Error(w, "invalid or expired session — please try again", http.StatusBadRequest)
		return
	}

	// Check for IdP error
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Printf("OIDC error during sessions login from %s: %s", remoteAddr(r), sanitizeForTerminal(errParam))
		http.Error(w, "authentication failed", http.StatusForbidden)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for token
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
		log.Printf("ERROR: sessions callback token exchange failed from %s", remoteAddr(r))
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Printf("ERROR: sessions callback no id_token from %s", remoteAddr(r))
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}

	idToken, err := s.verifier.Verify(exchangeCtx, rawIDToken)
	if err != nil {
		log.Printf("ERROR: sessions callback token verification failed from %s", remoteAddr(r))
		http.Error(w, "token verification failed", http.StatusInternalServerError)
		return
	}

	// Verify OIDC nonce
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(stateNonce)) != 1 {
		log.Printf("SECURITY: sessions callback nonce mismatch from %s", remoteAddr(r))
		http.Error(w, "token nonce mismatch", http.StatusBadRequest)
		return
	}

	var claims struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("ERROR: sessions callback claims parsing failed from %s", remoteAddr(r))
		http.Error(w, "failed to parse identity", http.StatusInternalServerError)
		return
	}

	username := claims.PreferredUsername
	if username == "" || !validUsername.MatchString(username) {
		log.Printf("SECURITY: sessions callback invalid username from %s", remoteAddr(r))
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}

	log.Printf("SESSIONS: user %q viewed sessions from %s", username, remoteAddr(r))

	// Render session list (reusing same pattern as approval success page)
	sessions := s.store.ActiveSessions(username)
	type sessionView struct {
		Hostname  string
		Remaining string
		CSRFToken string
		CSRFTs    string
	}
	var sessionViews []sessionView
	now := time.Now()
	csrfTs := fmt.Sprintf("%d", now.Unix())
	for _, sess := range sessions {
		csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)
		sessionViews = append(sessionViews, sessionView{
			Hostname:  sess.Hostname,
			Remaining: formatDuration(time.Until(sess.ExpiresAt)),
			CSRFToken: csrfToken,
			CSRFTs:    csrfTs,
		})
	}

	w.Header().Set("Content-Type", "text/html")
	if err := sessionsListTmpl.Execute(w, map[string]interface{}{
		"Username": username,
		"Sessions": sessionViews,
	}); err != nil {
		log.Printf("ERROR: sessions template execution: %v", err)
	}
}

// buildClientConfig returns a client config override map if any fields are set,
// or nil if no overrides are configured.
func (s *Server) buildClientConfig() map[string]interface{} {
	cfg := make(map[string]interface{})
	if s.cfg.ClientBreakglassPasswordType != "" {
		cfg["breakglass_password_type"] = s.cfg.ClientBreakglassPasswordType
	}
	if s.cfg.ClientBreakglassRotationDays > 0 {
		cfg["breakglass_rotation_days"] = s.cfg.ClientBreakglassRotationDays
	}
	if s.cfg.ClientTokenCacheEnabled != nil {
		cfg["token_cache_enabled"] = *s.cfg.ClientTokenCacheEnabled
	}
	if len(cfg) == 0 {
		return nil
	}
	return cfg
}

// handleBreakglassEscrow receives a break-glass password from a client and
// passes it to the configured escrow command.
// POST /api/breakglass/escrow
func (s *Server) handleBreakglassEscrow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Escrow endpoint ALWAYS requires authentication — even with PAM_POCKETID_INSECURE=true.
	// Unlike the challenge API, this endpoint executes a shell command with caller-provided
	// data on stdin, so unauthenticated access would be a command execution vector.
	if s.cfg.SharedSecret == "" {
		http.Error(w, "escrow endpoint requires shared secret authentication", http.StatusForbidden)
		return
	}

	if !s.verifySharedSecret(r) {
		authFailures.Inc()
		log.Printf("AUTH_FAILURE: invalid shared secret from %s on POST /api/breakglass/escrow", remoteAddr(r))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Hostname string `json:"hostname"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, "password required", http.StatusBadRequest)
		return
	}
	// Hostname is required for escrow (used for per-host token verification
	// and as the key in the escrow command's BREAKGLASS_HOSTNAME env var).
	if req.Hostname == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}
	if !validHostname.MatchString(req.Hostname) {
		http.Error(w, "invalid hostname format", http.StatusBadRequest)
		return
	}

	// Verify per-host escrow token to prevent a compromised host from
	// planting a known password for a different host. The token is
	// HMAC(shared_secret, "escrow:" + hostname), so each host can only
	// escrow for its own hostname.
	if s.cfg.SharedSecret != "" {
		expectedToken := computeEscrowToken(s.cfg.SharedSecret, req.Hostname)
		providedToken := r.Header.Get("X-Escrow-Token")
		if subtle.ConstantTimeCompare([]byte(expectedToken), []byte(providedToken)) != 1 {
			log.Printf("AUTH_FAILURE: invalid escrow token for host %q from %s", req.Hostname, remoteAddr(r))
			http.Error(w, "invalid escrow token for hostname", http.StatusForbidden)
			return
		}
	}

	if s.cfg.EscrowCommand == "" {
		log.Printf("BREAKGLASS: escrow received from host %q but no escrow command configured — password discarded", req.Hostname)
		http.Error(w, "escrow not configured on server", http.StatusNotImplemented)
		return
	}

	// Limit concurrent escrow command executions
	select {
	case escrowSemaphore <- struct{}{}:
		defer func() { <-escrowSemaphore }()
	default:
		http.Error(w, "too many concurrent escrow operations", http.StatusServiceUnavailable)
		return
	}

	// Execute escrow command with password on stdin and hostname as env var.
	// Password is NOT passed as an argument to avoid /proc/cmdline exposure.
	// Use a minimal environment to avoid leaking server secrets (CLIENT_SECRET,
	// SHARED_SECRET, etc.) to the escrow command.
	ctx, cancel := context.WithTimeout(r.Context(), escrowTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", s.cfg.EscrowCommand)
	cmd.Stdin = strings.NewReader(req.Password)
	// Start with minimal env, then add configured passthrough prefixes.
	// This prevents leaking server secrets while allowing cloud CLI tools
	// (AWS, Vault, etc.) to function when explicitly configured via
	// PAM_POCKETID_ESCROW_ENV=AWS_,VAULT_,OP_
	cmdEnv := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"BREAKGLASS_HOSTNAME=" + req.Hostname,
	}
	if len(s.cfg.EscrowEnvPassthrough) > 0 {
		for _, env := range os.Environ() {
			// Skip vars that are already in the baseline to prevent shadowing
			if strings.HasPrefix(env, "PATH=") || strings.HasPrefix(env, "HOME=") || strings.HasPrefix(env, "BREAKGLASS_HOSTNAME=") {
				continue
			}
			for _, prefix := range s.cfg.EscrowEnvPassthrough {
				if prefix != "" && strings.HasPrefix(env, prefix) {
					cmdEnv = append(cmdEnv, env)
					break
				}
			}
		}
	}
	cmd.Env = cmdEnv

	// Use separate capped buffers instead of CombinedOutput() to prevent
	// memory exhaustion from a verbose or malicious escrow command.
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdoutBuf, n: escrowMaxOutput}
	cmd.Stderr = &limitedWriter{w: &stderrBuf, n: escrowMaxOutput}

	if err := cmd.Run(); err != nil {
		breakglassEscrowTotal.WithLabelValues("failure").Inc()
		combined := truncateOutput(stdoutBuf.String() + stderrBuf.String())
		log.Printf("BREAKGLASS: escrow command failed for host %q: %v (output: %s)", req.Hostname, err, combined)
		http.Error(w, "escrow command failed", http.StatusInternalServerError)
		return
	}

	breakglassEscrowTotal.WithLabelValues("success").Inc()
	log.Printf("BREAKGLASS: password escrowed for host %q", req.Hostname)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
// Templates share a common CSS design system with dark mode support via
// CSS custom properties and @media (prefers-color-scheme: dark).

// sharedCSS is the common design system embedded in every template.
// Uses CSS custom properties for dark mode, Inter/system font stack,
// and professional styling inspired by Pocket ID / Tinyauth.
const sharedCSS = `
    :root {
      --bg: #f3f4f6;
      --card-bg: #ffffff;
      --text: #111827;
      --text-secondary: #6b7280;
      --border: #e5e7eb;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --primary-text: #ffffff;
      --success: #059669;
      --success-bg: #ecfdf5;
      --success-border: #a7f3d0;
      --danger: #dc2626;
      --danger-bg: #fef2f2;
      --danger-border: #fecaca;
      --warning: #d97706;
      --warning-bg: #fffbeb;
      --warning-border: #fde68a;
      --info-bg: #eff6ff;
      --info-border: #bfdbfe;
      --code-bg: #f9fafb;
      --code-border: #d1d5db;
      --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 24px rgba(0,0,0,0.05);
      --focus-ring: 0 0 0 3px rgba(59,130,246,0.4);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0f172a;
        --card-bg: #1e293b;
        --text: #f1f5f9;
        --text-secondary: #94a3b8;
        --border: #334155;
        --primary: #60a5fa;
        --primary-hover: #3b82f6;
        --primary-text: #0f172a;
        --success: #34d399;
        --success-bg: #064e3b;
        --success-border: #065f46;
        --danger: #f87171;
        --danger-bg: #450a0a;
        --danger-border: #7f1d1d;
        --warning: #fbbf24;
        --warning-bg: #451a03;
        --warning-border: #78350f;
        --info-bg: #1e3a5f;
        --info-border: #1e40af;
        --code-bg: #0f172a;
        --code-border: #475569;
        --shadow: 0 1px 3px rgba(0,0,0,0.3), 0 4px 24px rgba(0,0,0,0.2);
      }
    }
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif;
      max-width: 440px;
      margin: 0 auto;
      padding: 48px 20px;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }
    .card {
      background: var(--card-bg);
      border-radius: 16px;
      padding: 40px 32px;
      box-shadow: var(--shadow);
      border: 1px solid var(--border);
      width: 100%;
      text-align: center;
    }
    h2 {
      font-size: 1.375rem;
      font-weight: 700;
      margin: 12px 0 8px;
      letter-spacing: -0.01em;
    }
    p { margin: 8px 0; color: var(--text-secondary); font-size: 0.938rem; }
    .icon {
      width: 56px;
      height: 56px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 8px;
      font-size: 1.5rem;
    }
    strong { color: var(--text); font-weight: 600; }
`

const approvalPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Sudo approval</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .shield {
      background: var(--info-bg);
      border: 2px solid var(--info-border);
      color: var(--primary);
      position: relative;
    }
    .lock-icon {
      display: inline-block;
      width: 18px;
      height: 14px;
      border: 3px solid var(--primary);
      border-radius: 3px;
      position: relative;
      top: 3px;
    }
    .lock-icon::before {
      content: '';
      display: block;
      width: 10px;
      height: 9px;
      border: 3px solid var(--primary);
      border-bottom: none;
      border-radius: 8px 8px 0 0;
      position: absolute;
      top: -11px;
      left: 1px;
    }
    .request-info { margin: 20px 0 4px; }
    .request-info p { color: var(--text); font-size: 0.938rem; }
    .user { color: var(--primary); font-weight: 700; }
    .host { color: var(--text); font-weight: 600; }
    .code-label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      margin: 20px 0 8px;
    }
    .code {
      display: inline-block;
      font-size: clamp(1.125rem, 5vw, 1.75rem);
      font-weight: 700;
      letter-spacing: 0.12em;
      color: var(--text);
      font-family: 'SF Mono', SFMono-Regular, ui-monospace, Menlo, Consolas, monospace;
      background: var(--code-bg);
      border: 2px solid var(--code-border);
      border-radius: 12px;
      padding: 12px 20px;
      margin: 0 0 4px;
      max-width: 100%;
      word-break: break-all;
    }
    .code-hint {
      font-size: 0.813rem;
      color: var(--text-secondary);
      margin: 8px 0 20px;
    }
    .duration-group { display: flex; flex-wrap: wrap; gap: 0; margin: 20px 0; justify-content: center; }
    .duration-btn { padding: 12px 20px; border: 2px solid var(--border); text-decoration: none; color: var(--text); font-weight: 600; font-size: 0.938rem; min-height: 44px; display: flex; align-items: center; justify-content: center; }
    .duration-btn:first-child { border-radius: 10px 0 0 10px; }
    .duration-btn:last-child { border-radius: 0 10px 10px 0; }
    .duration-btn + .duration-btn { border-left: none; }
    .duration-btn.active { background: var(--primary); color: var(--primary-text); border-color: var(--primary); }
    .duration-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); z-index: 1; position: relative; }
    .duration-btn:hover { background: var(--info-bg); }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: var(--primary);
      color: var(--primary-text);
      padding: 12px 32px;
      border-radius: 10px;
      text-decoration: none;
      font-size: 0.938rem;
      font-weight: 600;
      border: none;
      cursor: pointer;
      transition: background 0.15s ease, box-shadow 0.15s ease, transform 0.1s ease;
      width: 100%;
      max-width: 320px;
    }
    .btn:hover { background: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.3); }
    .btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
    .btn:active { transform: translateY(0); }
    .warn {
      color: var(--text-secondary);
      font-size: 0.813rem;
      margin-top: 20px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
    }
    .duration-label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      margin: 16px 0 4px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon shield" aria-hidden="true"><div class="lock-icon"></div></div>
    <h2>Sudo elevation request</h2>
    <div class="request-info">
      <p>User <strong class="user">{{.Username}}</strong>{{if .Hostname}} on <strong class="host">{{.Hostname}}</strong>{{end}} is requesting sudo access.</p>
    </div>
    <div class="code-label">Verification code</div>
    <div class="code" aria-label="Verification code: {{.Code}}">{{.Code}}</div>
    <p class="code-hint">Verify this code matches your terminal</p>
    {{if .Durations}}<div class="duration-label">Session duration</div>
    <div class="duration-group" role="group" aria-label="Session duration">{{range .Durations}}<a href="{{$.LoginURL}}?duration={{.Seconds}}" class="duration-btn{{if .Active}} active{{end}}" role="button"{{if .Active}} aria-current="true"{{end}}>{{.Label}}</a>{{end}}</div>
    {{else}}
    <a href="{{.LoginURL}}" class="btn" role="button" aria-label="Authenticate with Pocket ID to approve this sudo request">Authenticate with Pocket ID</a>
    {{end}}
    <p class="warn">If you did not request this, close this page.</p>
  </div>
</body>
</html>`

const approvalSuccessHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Sudo approved</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-success {
      background: var(--success-bg);
      border: 2px solid var(--success-border);
      color: var(--success);
    }
    h2 { color: var(--success); }
    .session-list { text-align: left; margin: 20px 0; }
    .session-row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); gap: 12px; }
    .session-info { min-width: 0; flex: 1; }
    .session-host { font-weight: 600; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .session-time { color: var(--text-secondary); font-size: 0.813rem; display: block; }
    .revoke-btn { background: none; border: 1px solid var(--danger); color: var(--danger); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.813rem; font-weight: 600; min-height: 36px; white-space: nowrap; flex-shrink: 0; }
    .revoke-btn:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(220,38,38,0.4); }
    .revoke-btn:hover { background: var(--danger-bg); }
    .session-label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      margin: 24px 0 8px;
      text-align: left;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-success" aria-hidden="true">&#x2713;</div>
    <h2>Sudo approved</h2>
    <p>You're all set. Your terminal session will continue.</p>
    {{if .Sessions}}
    <div class="session-label">Your active sessions</div>
    <div class="session-list" role="list" aria-label="Active sessions">
      {{range .Sessions}}
      <div class="session-row" role="listitem">
        <div class="session-info">
          <span class="session-host">{{.Hostname}}</span>
          <span class="session-time">{{.Remaining}} remaining</span>
        </div>
        <form method="POST" action="/api/sessions/revoke">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
          <button type="submit" class="revoke-btn" aria-label="Revoke session on {{.Hostname}}">Revoke</button>
        </form>
      </div>
      {{end}}
    </div>
    {{end}}
  </div>
</body>
</html>`

const approvalDeniedHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Request denied</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-danger {
      background: var(--danger-bg);
      border: 2px solid var(--danger-border);
      color: var(--danger);
    }
    h2 { color: var(--danger); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-danger" aria-hidden="true">&#x2717;</div>
    <h2>Request denied</h2>
    <p>The authentication was not completed. You may need to run your sudo command again.</p>
  </div>
</body>
</html>`

// approvalMismatchHTML uses html/template syntax so user-controlled values are safely escaped.
const approvalMismatchHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Identity mismatch</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-danger {
      background: var(--danger-bg);
      border: 2px solid var(--danger-border);
      color: var(--danger);
    }
    h2 { color: var(--danger); }
    .detail {
      background: var(--danger-bg);
      border: 1px solid var(--danger-border);
      border-radius: 10px;
      padding: 16px 20px;
      margin: 16px 0;
      text-align: left;
      font-size: 0.875rem;
      color: var(--text);
      line-height: 1.7;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-danger" aria-hidden="true">&#x2717;</div>
    <h2>Identity mismatch</h2>
    <div class="detail">
      <p>You authenticated as <strong>{{.AuthenticatedUser}}</strong>, but the sudo request is for <strong>{{.ExpectedUser}}</strong>.</p>
    </div>
    <p>Sign out of Pocket ID and authenticate as the correct user, then run your sudo command again.</p>
  </div>
</body>
</html>`

const approvalExpiredHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Request expired</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-warning {
      background: var(--warning-bg);
      border: 2px solid var(--warning-border);
      color: var(--warning);
    }
    h2 { color: var(--warning); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-warning" aria-hidden="true">&#x23f0;</div>
    <h2>Request expired</h2>
    <p>This approval request has expired or was not found.</p>
    <p>Run your sudo command again to create a new request.</p>
  </div>
</body>
</html>`

// approvalAlreadyHTML uses html/template syntax so the status is safely escaped.
const approvalAlreadyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Already resolved</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-info {
      background: var(--info-bg);
      border: 2px solid var(--info-border);
      color: var(--primary);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-info" aria-hidden="true">&#x2139;</div>
    <h2>Already resolved</h2>
    <p>This sudo request has already been <strong>{{.Status}}</strong>.</p>
  </div>
</body>
</html>`

const sessionsListHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Your active sessions</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
    .icon-info {
      background: var(--info-bg);
      border: 2px solid var(--info-border);
      color: var(--primary);
    }
    .session-list { text-align: left; margin: 20px 0; }
    .session-row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); gap: 12px; }
    .session-info { min-width: 0; flex: 1; }
    .session-host { font-weight: 600; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .session-time { color: var(--text-secondary); font-size: 0.813rem; display: block; }
    .revoke-btn { background: none; border: 1px solid var(--danger); color: var(--danger); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.813rem; font-weight: 600; min-height: 36px; white-space: nowrap; flex-shrink: 0; }
    .revoke-btn:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(220,38,38,0.4); }
    .revoke-btn:hover { background: var(--danger-bg); }
    .session-label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      margin: 24px 0 8px;
      text-align: left;
    }
    .empty-state { color: var(--text-secondary); margin: 24px 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-info" aria-hidden="true">&#x1f511;</div>
    <h2>Your active sessions</h2>
    <p>Signed in as <strong>{{.Username}}</strong></p>
    {{if .Sessions}}
    <div class="session-label">Active grace periods</div>
    <div class="session-list" role="list" aria-label="Active sessions">
      {{range .Sessions}}
      <div class="session-row" role="listitem">
        <div class="session-info">
          <span class="session-host">{{.Hostname}}</span>
          <span class="session-time">{{.Remaining}} remaining</span>
        </div>
        <form method="POST" action="/api/sessions/revoke">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
          <button type="submit" class="revoke-btn" aria-label="Revoke session on {{.Hostname}}">Revoke</button>
        </form>
      </div>
      {{end}}
    </div>
    {{else}}
    <p class="empty-state">You have no active sudo sessions.</p>
    {{end}}
  </div>
</body>
</html>`
