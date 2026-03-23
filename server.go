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
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
)

// serverStartTime records when the process started, used by the info page.
var serverStartTime = time.Now()

// templateFuncMap is the shared function map for all templates.
var templateFuncMap = template.FuncMap{
	"formatDuration": formatDuration,
	"timeAgo":        timeAgo,
	"formatTime":     formatTime,
	"actionLabel":    actionLabel,
	"eq":             func(a, b string) bool { return a == b },
	"eqInt":          func(a, b int) bool { return a == b },
	"add":            func(a, b int) int { return a + b },
	"sub":            func(a, b int) int { return a - b },
}

// Pre-parsed templates — avoids re-parsing on every request.
var (
	approvalAlreadyTmpl  = template.Must(template.New("already").Parse(approvalAlreadyHTML))
	approvalExpiredTmpl  = template.Must(template.New("expired").Parse(approvalExpiredHTML))
	approvalMismatchTmpl = template.Must(template.New("mismatch").Parse(approvalMismatchHTML))
	dashboardTmpl        = template.Must(template.New("dashboard").Funcs(templateFuncMap).Parse(dashboardHTML))
	historyTmpl          = template.Must(template.New("history").Funcs(templateFuncMap).Parse(historyPageHTML))
	hostsTmpl            = template.Must(template.New("hosts").Funcs(templateFuncMap).Parse(hostsPageHTML))
	infoTmpl             = template.Must(template.New("info").Funcs(templateFuncMap).Parse(infoPageHTML))
	loginPageTmpl        = template.Must(template.New("login").Parse(loginPageHTML))
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
	hostRegistry   *HostRegistry
	oidcConfig     oauth2.Config
	verifier       *oidc.IDTokenVerifier
	mux            *http.ServeMux
	notifyWg       sync.WaitGroup // tracks in-flight notification goroutines for graceful shutdown
	sessionNonces  map[string]time.Time // nonce -> creation time for /sessions OIDC flow
	sessionNonceMu sync.Mutex
	sseClients     map[string][]chan string // username -> list of SSE channels
	sseMu          sync.Mutex
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
		hostRegistry:  NewHostRegistry(cfg.HostRegistryFile),
		oidcConfig:    oidcConfig,
		verifier:      verifier,
		mux:           http.NewServeMux(),
		sessionNonces: make(map[string]time.Time),
		sseClients:    make(map[string][]chan string),
	}

	s.mux.HandleFunc("/api/challenge", s.handleCreateChallenge)
	s.mux.HandleFunc("/api/challenge/", s.handlePollChallenge)
	s.mux.HandleFunc("/api/challenges/approve", s.handleBulkApprove)
	s.mux.HandleFunc("/api/challenges/approve-all", s.handleBulkApproveAll)
	s.mux.HandleFunc("/api/challenges/reject", s.handleRejectChallenge)
	s.mux.HandleFunc("/api/challenges/reject-all", s.handleRejectAll)
	s.mux.HandleFunc("/api/grace-status", s.handleGraceStatus)
	s.mux.HandleFunc("/api/breakglass/escrow", s.handleBreakglassEscrow)
	s.mux.HandleFunc("/api/sessions/revoke", s.handleRevokeSession)
	s.mux.HandleFunc("/api/sessions/revoke-all", s.handleRevokeAll)
	s.mux.HandleFunc("/api/sessions/extend", s.handleExtendSession)
	s.mux.HandleFunc("/api/sessions/extend-all", s.handleExtendAll)
	s.mux.HandleFunc("/api/history/export", s.handleHistoryExport)
	s.mux.HandleFunc("/api/events", s.handleSSEEvents)
	s.mux.HandleFunc("/approve/", s.handleApprovalPage)
	s.mux.HandleFunc("/callback", s.handleOIDCCallback)
	s.mux.HandleFunc("/sessions", s.handleSessionsRedirect)
	s.mux.HandleFunc("/sessions/login", s.handleSessionsLogin)
	s.mux.HandleFunc("/history", s.handleHistoryPage)
	s.mux.HandleFunc("/hosts", s.handleHostsPage)
	s.mux.HandleFunc("/info", s.handleInfoPage)
	s.mux.HandleFunc("/api/hosts/elevate", s.handleElevate)
	s.mux.HandleFunc("/api/hosts/rotate", s.handleRotateHost)
	s.mux.HandleFunc("/api/hosts/rotate-all", s.handleRotateAllHosts)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.Handle("/metrics", promhttp.Handler())
	s.mux.HandleFunc("/api/onetap/", s.handleOneTap)
	s.mux.HandleFunc("/theme", s.handleThemeToggle)
	s.mux.HandleFunc("/signout", s.handleSignOut)
	// Dashboard is the catch-all — register AFTER all other routes.
	s.mux.HandleFunc("/", s.handleDashboard)

	return s, nil
}

// Stop cleanly shuts down the server's background resources.
func (s *Server) Stop() {
	s.store.Stop()
}

// registerSSE creates a new SSE channel for the given username and returns it.
func (s *Server) registerSSE(username string) chan string {
	ch := make(chan string, 16)
	s.sseMu.Lock()
	s.sseClients[username] = append(s.sseClients[username], ch)
	s.sseMu.Unlock()
	return ch
}

// unregisterSSE removes the given channel from the SSE client list for username.
func (s *Server) unregisterSSE(username string, ch chan string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	clients := s.sseClients[username]
	for i, c := range clients {
		if c == ch {
			s.sseClients[username] = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	if len(s.sseClients[username]) == 0 {
		delete(s.sseClients, username)
	}
}

// broadcastSSE sends an event string to all SSE channels registered for username,
// and also to the "__admin__" channel so admins see all events.
func (s *Server) broadcastSSE(username, event string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	for _, ch := range s.sseClients[username] {
		select {
		case ch <- event:
		default: // drop if channel full
		}
	}
	// Also broadcast to admin subscribers
	for _, ch := range s.sseClients["__admin__"] {
		select {
		case ch <- event:
		default:
		}
	}
}

// handleSSEEvents streams server-sent events for live dashboard updates.
// GET /api/events
func (s *Server) handleSSEEvents(w http.ResponseWriter, r *http.Request) {
	username := s.getSessionUser(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	// Admin users subscribe to the "__admin__" channel to see all users' events.
	sseKey := username
	if s.getSessionRole(r) == "admin" {
		sseKey = "__admin__"
	}
	ch := s.registerSSE(sseKey)
	defer s.unregisterSSE(sseKey, ch)

	// Send initial keepalive
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-ch:
			fmt.Fprintf(w, "event: update\ndata: %s\n\n", event)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// ServeHTTP implements http.Handler. Adds security headers and panic recovery.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rv := recover(); rv != nil {
			log.Printf("ERROR: panic in handler from %s: %v", remoteAddr(r), rv)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	// Generate a per-request nonce for the timezone detection script.
	// This allows a single inline script while keeping CSP strict.
	nonce, err := randomHex(16)
	if err != nil {
		log.Printf("ERROR: generating CSP nonce: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'nonce-%s'; style-src 'unsafe-inline'; img-src 'self' https:; frame-ancestors 'none'", nonce))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	// Store nonce in request context for templates
	ctx := context.WithValue(r.Context(), "csp-nonce", nonce)
	r = r.WithContext(ctx)
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

// verifyAPISecret checks the X-Shared-Secret header against both the global shared
// secret and any registered host secret. Used for API endpoints (poll, grace-status,
// escrow) where the hostname isn't known at auth time.
func (s *Server) verifyAPISecret(r *http.Request) bool {
	if s.verifySharedSecret(r) {
		return true
	}
	// Check if the provided secret matches any registered host
	if s.hostRegistry.IsEnabled() {
		provided := r.Header.Get("X-Shared-Secret")
		if provided != "" {
			return s.hostRegistry.ValidateAnyHost(provided)
		}
	}
	return false
}

// verifyAPIKey checks the Authorization: Bearer header against configured API keys.
// Returns true only when at least one key is configured and the token matches.
func (s *Server) verifyAPIKey(r *http.Request) bool {
	if len(s.cfg.APIKeys) == 0 {
		return false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	for _, key := range s.cfg.APIKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

// authenticateChallenge checks whether a challenge creation request is authorized.
// Tries the global shared secret first, then per-host secrets from the registry.
// Returns (authorized bool, errorMsg string). When authorized is false, errorMsg
// describes why.
func (s *Server) authenticateChallenge(r *http.Request, hostname, username string) (bool, string) {
	// Try global shared secret first
	if s.verifySharedSecret(r) {
		// Check user authorization if registry is enabled
		if s.hostRegistry.IsEnabled() && hostname != "" {
			if !s.hostRegistry.IsUserAuthorized(hostname, username) {
				return false, "user not authorized on this host"
			}
		}
		return true, ""
	}
	// Try per-host secret from registry
	if s.hostRegistry.IsEnabled() && hostname != "" {
		providedSecret := r.Header.Get("X-Shared-Secret")
		if s.hostRegistry.ValidateHost(hostname, providedSecret) {
			if !s.hostRegistry.IsUserAuthorized(hostname, username) {
				return false, "user not authorized on this host"
			}
			return true, ""
		}
	}
	return false, "unauthorized"
}

// remoteAddr extracts the client IP from a request for logging.
func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sessionCookieName is the name of the signed session cookie.
const sessionCookieName = "pam_session"

// sessionCookieTTL is the max-age for the session cookie (30 minutes).
const sessionCookieTTL = 30 * time.Minute

// setSessionCookie sets a signed session cookie on the response.
// role should be "admin" or "user".
func (s *Server) setSessionCookie(w http.ResponseWriter, username, role string) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	mac.Write([]byte("session:" + username + ":" + role + ":" + ts))
	sig := hex.EncodeToString(mac.Sum(nil))
	value := username + ":" + role + ":" + ts + ":" + sig
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sessionCookieTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if strings.HasPrefix(s.cfg.ExternalURL, "https://") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

// getSessionUser validates the session cookie and returns the username, or "" if invalid/expired.
func (s *Server) getSessionUser(r *http.Request) string {
	if s.cfg.SharedSecret == "" {
		return ""
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	// Support new format: username:role:ts:sig (4 parts)
	// and legacy format: username:ts:sig (3 parts)
	parts := strings.SplitN(cookie.Value, ":", 4)
	if len(parts) == 4 {
		username, role, ts, sig := parts[0], parts[1], parts[2], parts[3]
		if !validUsername.MatchString(username) {
			return ""
		}
		if role != "admin" && role != "user" {
			return ""
		}
		tsInt, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return ""
		}
		if time.Since(time.Unix(tsInt, 0)).Abs() > sessionCookieTTL {
			return ""
		}
		mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
		mac.Write([]byte("session:" + username + ":" + role + ":" + ts))
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
			return ""
		}
		return username
	}
	if len(parts) == 3 {
		// Legacy format: username:ts:sig
		username, ts, sig := parts[0], parts[1], parts[2]
		if !validUsername.MatchString(username) {
			return ""
		}
		tsInt, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return ""
		}
		if time.Since(time.Unix(tsInt, 0)).Abs() > sessionCookieTTL {
			return ""
		}
		mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
		mac.Write([]byte("session:" + username + ":" + ts))
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
			return ""
		}
		return username
	}
	return ""
}

// getSessionRole returns the role embedded in the session cookie: "admin" or "user".
// Returns "user" if the cookie uses the legacy format or if the role is not "admin".
func (s *Server) getSessionRole(r *http.Request) string {
	if s.cfg.SharedSecret == "" {
		return "user"
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "user"
	}
	parts := strings.SplitN(cookie.Value, ":", 4)
	if len(parts) == 4 {
		username, role, ts, sig := parts[0], parts[1], parts[2], parts[3]
		if !validUsername.MatchString(username) {
			return "user"
		}
		if role != "admin" && role != "user" {
			return "user"
		}
		tsInt, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return "user"
		}
		if time.Since(time.Unix(tsInt, 0)).Abs() > sessionCookieTTL {
			return "user"
		}
		mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
		mac.Write([]byte("session:" + username + ":" + role + ":" + ts))
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
			return "user"
		}
		return role
	}
	return "user"
}

// requiresAdminApproval checks if a hostname matches the admin approval policy.
// Patterns use filepath.Match glob syntax (e.g., "*.prod", "bastion-*").
func (s *Server) requiresAdminApproval(hostname string) bool {
	for _, pattern := range s.cfg.AdminApprovalHosts {
		if matched, _ := filepath.Match(pattern, hostname); matched {
			return true
		}
	}
	return false
}

// setFlashCookie sets a short-lived cookie containing a flash message.
// The cookie is read and cleared on the next page load.
func setFlashCookie(w http.ResponseWriter, flash string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "pam_flash",
		Value:    flash,
		Path:     "/",
		MaxAge:   10,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// getAndClearFlash reads the pam_flash cookie, clears it, and returns the value.
func getAndClearFlash(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("pam_flash")
	if err != nil || cookie.Value == "" {
		return ""
	}
	// Clear the cookie immediately
	http.SetCookie(w, &http.Cookie{
		Name:     "pam_flash",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return cookie.Value
}

// getTheme reads the pam_theme cookie and returns "light", "dark", or "" (system default).
func getAvatar(r *http.Request) string {
	c, err := r.Cookie("pam_avatar")
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

func getTheme(r *http.Request) string {
	c, err := r.Cookie("pam_theme")
	if err != nil || c.Value == "" {
		return "" // system default
	}
	if c.Value == "light" || c.Value == "dark" {
		return c.Value
	}
	return ""
}

// handleThemeToggle sets the theme preference cookie based on the "set" query
// param and redirects back.
// GET /theme?set=dark|light|system&from=/path
func (s *Server) handleThemeToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.URL.Query().Get("set")
	switch target {
	case "dark":
		http.SetCookie(w, &http.Cookie{Name: "pam_theme", Value: "dark", Path: "/", MaxAge: 31536000, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	case "light":
		http.SetCookie(w, &http.Cookie{Name: "pam_theme", Value: "light", Path: "/", MaxAge: 31536000, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	default: // "system" or anything else — delete cookie
		http.SetCookie(w, &http.Cookie{Name: "pam_theme", Value: "", Path: "/", MaxAge: -1})
	}

	dest := r.URL.Query().Get("from")
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// handleSignOut clears the session cookie and redirects to OIDC login.
// GET /signout
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "pam_session", Value: "", Path: "/", MaxAge: -1})
	loginURL := strings.TrimRight(s.cfg.ExternalURL, "/") + "/sessions/login"
	http.Redirect(w, r, loginURL, http.StatusSeeOther)
}

// handleDashboard renders the main dashboard page.
// GET /
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// The "/" pattern is a catch-all in Go's ServeMux. Only handle exact "/" path.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	// Read and clear flash BEFORE auth check so login page can show flash messages.
	var flashes []string
	if flashParam := getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) == 2 {
				switch parts[0] {
				case "approved":
					flashes = append(flashes, t("approved_sudo_on")+" "+parts[1])
				case "revoked":
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1])
				case "approved_all":
					flashes = append(flashes, fmt.Sprintf(t("approved_n_requests"), atoi(parts[1])))
				case "revoked_all":
					flashes = append(flashes, fmt.Sprintf(t("revoked_n_sessions"), atoi(parts[1])))
				case "rejected":
					flashes = append(flashes, t("rejected_sudo_on")+" "+parts[1])
				case "rejected_all":
					flashes = append(flashes, fmt.Sprintf(t("rejected_n_requests"), atoi(parts[1])))
				case "elevated":
					flashes = append(flashes, t("elevated_session_on")+" "+parts[1])
				case "extended":
					flashes = append(flashes, t("extended_session_on")+" "+parts[1])
				case "extended_all":
					flashes = append(flashes, fmt.Sprintf(t("extended_n_sessions"), atoi(parts[1])))
				case "expired":
					flashes = append(flashes, t("session_expired_sign_in"))
				}
			}
		}
	}

	username := s.getSessionUser(r)
	if username == "" {
		// Auto-redirect to OIDC login — no intermediate page
		loginURL := strings.TrimRight(s.cfg.ExternalURL, "/") + "/sessions/login"
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	// Refresh session cookie on every dashboard page load (sliding 30-min window).
	s.setSessionCookie(w, username, s.getSessionRole(r))

	// Determine if this user has admin role
	isAdmin := s.getSessionRole(r) == "admin"

	// Build data for the dashboard
	var pending []Challenge
	var sessions []GraceSession
	if isAdmin {
		pending = s.store.AllPendingChallenges()
		sessions = s.store.AllActiveSessions()
	} else {
		pending = s.store.PendingChallenges(username)
		sessions = s.store.ActiveSessions(username)
	}
	var allHistory []ActionLogEntry
	if isAdmin {
		allHistory = s.store.AllActionHistory()
	} else {
		allHistory = s.store.ActionHistory(username)
	}
	// Limit dashboard to most recent 5 entries
	history := allHistory
	if len(history) > 5 {
		history = history[:5]
	}

	now := time.Now()
	csrfTs := fmt.Sprintf("%d", now.Unix())
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	type pendingView struct {
		ID            string
		Username      string
		Hostname      string
		Code          string
		ExpiresIn     string
		AdminRequired bool
	}
	// Sort pending challenges by expiry (most urgent first)
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].ExpiresAt.Before(pending[j].ExpiresAt)
	})

	var pendingViews []pendingView
	for _, c := range pending {
		hostname := c.Hostname
		if hostname == "" {
			hostname = t("unknown_host")
		}
		pendingViews = append(pendingViews, pendingView{
			ID:            c.ID,
			Username:      c.Username,
			Hostname:      hostname,
			Code:          c.UserCode,
			ExpiresIn:     formatDuration(time.Until(c.ExpiresAt)),
			AdminRequired: s.requiresAdminApproval(c.Hostname),
		})
	}

	type sessionView struct {
		Username  string
		Hostname  string
		Remaining string
		ExpiresAt time.Time
	}
	var sessionViews []sessionView
	for _, sess := range sessions {
		sessHostname := sess.Hostname
		if sessHostname == "(unknown)" {
			sessHostname = t("unknown_host")
		}
		sessionViews = append(sessionViews, sessionView{
			Username:  sess.Username,
			Hostname:  sessHostname,
			Remaining: formatDuration(time.Until(sess.ExpiresAt)),
			ExpiresAt: sess.ExpiresAt,
		})
	}
	// Sort sessions by expiry (least time remaining first)
	sort.Slice(sessionViews, func(i, j int) bool {
		return sessionViews[i].ExpiresAt.Before(sessionViews[j].ExpiresAt)
	})

	// Read timezone from cookie for profile dropdown display
	dashTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			dashTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := dashboardTmpl.Execute(w, map[string]interface{}{
		"Username":       username,
		"Initial":        strings.ToUpper(username[:1]),
		"Avatar":         getAvatar(r),
		"Timezone":       dashTZ,
		"Flashes":        flashes,
		"Pending":        pendingViews,
		"Sessions":       sessionViews,
		"History":        history,
		"HasMoreHistory": len(allHistory) > 5,
		"CSRFToken":      csrfToken,
		"CSRFTs":         csrfTs,
		"ActivePage":     "sessions",
		"Theme":          getTheme(r),
		"CSPNonce":       r.Context().Value("csp-nonce"),
		"T":              T(lang),
		"Lang":           lang,
		"Languages":      supportedLanguages,
		"IsAdmin":        isAdmin,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

// handleSessionsRedirect redirects /sessions to the dashboard.
func (s *Server) handleSessionsRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
}

// handleCreateChallenge creates a new sudo challenge.
// POST /api/challenge {"username": "jordan"}
func (s *Server) handleCreateChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

	// Authenticate: try global shared secret, then per-host secret from registry.
	// We parse the body first so we have the hostname for per-host auth.
	authorized, errMsg := s.authenticateChallenge(r, req.Hostname, req.Username)
	if !authorized {
		authFailures.Inc()
		log.Printf("AUTH_FAILURE: %s from %s on POST /api/challenge (host=%q, user=%q)", errMsg, remoteAddr(r), req.Hostname, req.Username)
		if errMsg == "user not authorized on this host" {
			http.Error(w, errMsg, http.StatusForbidden)
		} else {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
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
	s.broadcastSSE(req.Username, "challenge_created")

	// Build client_config if any server-side client overrides are set
	clientCfg := s.buildClientConfig()

	// Auto-approve if within grace period
	if s.store.WithinGracePeriod(req.Username, req.Hostname) {
		if err := s.store.AutoApprove(challenge.ID); err == nil {
			challengesAutoApproved.Inc()
			activeChallenges.Dec()
			challengeDuration.Observe(0)
			log.Printf("GRACE: auto-approved sudo for user %q (challenge %s) — recent authentication within grace period", req.Username, challenge.ID[:8])
			hostname := req.Hostname
			if hostname == "" {
				hostname = "(unknown)"
			}
			s.store.LogAction(req.Username, "auto_approved", hostname, challenge.UserCode, "")

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
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("ERROR: writing JSON response: %v", err)
			}
			return
		}
	}

	approvalURL := fmt.Sprintf("%s/approve/%s", strings.TrimRight(s.cfg.ExternalURL, "/"), challenge.UserCode)

	oneTapToken := s.computeOneTapToken(challenge.ID, challenge.ExpiresAt)
	oneTapURL := ""
	if oneTapToken != "" {
		oneTapURL = strings.TrimRight(s.cfg.ExternalURL, "/") + "/api/onetap/" + oneTapToken
	}

	// Fire push notification asynchronously (no-op if not configured).
	s.sendNotification(challenge, approvalURL, oneTapURL)
	// sendWebhookNotifications spawns one goroutine per configured webhook; no
	// extra goroutine wrapper needed here.
	s.sendWebhookNotifications(webhookData{
		Username:    challenge.Username,
		Hostname:    challenge.Hostname,
		UserCode:    challenge.UserCode,
		ApprovalURL: approvalURL,
		OneTapURL:   oneTapURL,
		ExpiresIn:   int(s.cfg.ChallengeTTL.Seconds()),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	})

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
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("ERROR: writing JSON response: %v", err)
	}
}

// handlePollChallenge checks challenge status.
// GET /api/challenge/{id}
func (s *Server) handlePollChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.verifyAPISecret(r) {
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
		if err := json.NewEncoder(w).Encode(map[string]string{"status": string(StatusExpired)}); err != nil {
			log.Printf("ERROR: writing JSON response: %v", err)
		}
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
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("ERROR: writing JSON response: %v", err)
	}
}

// handleGraceStatus returns the grace period remaining for a user@host.
// GET /api/grace-status?username=X&hostname=Y
// Used by the PAM client to get the accurate grace time on cache hits.
func (s *Server) handleGraceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyAPISecret(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	username := r.URL.Query().Get("username")
	hostname := r.URL.Query().Get("hostname")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if !validUsername.MatchString(username) {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}
	if hostname != "" && !validHostname.MatchString(hostname) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}
	remaining := s.store.GraceRemaining(username, hostname)
	resp := map[string]interface{}{
		"grace_remaining": int(remaining.Seconds()),
	}
	if t := s.store.RevokeTokensBefore(username); !t.IsZero() {
		resp["revoke_tokens_before"] = t.Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("ERROR: writing JSON response: %v", err)
	}
}

// handleApprovalPage validates the code and redirects to OIDC login.
// After OIDC, the user lands on the dashboard where they can approve or reject.
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
		if err := approvalExpiredTmpl.Execute(w, map[string]string{
			"Theme": getTheme(r),
			"Lang":  detectLanguage(r),
		}); err != nil {
			log.Printf("ERROR: template execution: %v", err)
		}
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
			"Theme":  getTheme(r),
			"Lang":   detectLanguage(r),
		}); err != nil {
			log.Printf("ERROR: template execution: %v", err)
		}
		return
	}

	// Redirect to OIDC login — after authentication the user lands on the
	// dashboard where they can explicitly approve or reject the pending challenge.
	loginURL := strings.TrimRight(s.cfg.ExternalURL, "/") + "/sessions/login"
	http.Redirect(w, r, loginURL, http.StatusSeeOther)
}

// oidcExchangeTimeout limits how long we wait for the IdP token exchange.
// Prevents a slow/malicious IdP from holding goroutines indefinitely.
const oidcExchangeTimeout = 15 * time.Second

// handleOIDCCallback processes the OIDC callback after Pocket ID authentication.
// Only handles the sessions-based OIDC flow (state prefix "sessions:").
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := r.URL.Query().Get("state")

	// Only sessions-based OIDC flow is supported.
	if strings.HasPrefix(state, "sessions:") {
		s.handleSessionsCallback(w, r)
		return
	}

	log.Printf("SECURITY: callback with unexpected state format from %s", remoteAddr(r))
	revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "auth_state_unrecognized")
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

// computeOneTapToken creates a time-limited, single-use HMAC token for one-tap approval.
// Format: {challenge_id}.{expires_unix}.{hmac_hex}
func (s *Server) computeOneTapToken(challengeID string, expiresAt time.Time) string {
	if s.cfg.SharedSecret == "" {
		return ""
	}
	expires := fmt.Sprintf("%d", expiresAt.Unix())
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	mac.Write([]byte("onetap:" + challengeID + ":" + expires))
	sig := hex.EncodeToString(mac.Sum(nil))
	return challengeID + "." + expires + "." + sig
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

// verifyFormAuth checks the session cookie and CSRF token for form submissions.
// Returns the validated username, or writes a styled error page and returns "".
func (s *Server) verifyFormAuth(w http.ResponseWriter, r *http.Request) string {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_form")
		return ""
	}

	username := r.FormValue("username")
	csrfToken := r.FormValue("csrf_token")
	csrfTs := r.FormValue("csrf_ts")

	if username == "" || csrfToken == "" || csrfTs == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return ""
	}

	if !validUsername.MatchString(username) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_username_format")
		return ""
	}

	// Check session cookie matches form username
	if sessionUser := s.getSessionUser(r); sessionUser == "" || sessionUser != username {
		revokeErrorPage(w, r, http.StatusForbidden, "session_expired", "session_expired_sign_in")
		return ""
	}

	// Verify CSRF timestamp
	tsInt, err := strconv.ParseInt(csrfTs, 10, 64)
	if err != nil {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_timestamp")
		return ""
	}
	if time.Since(time.Unix(tsInt, 0)).Abs() > 5*time.Minute {
		revokeErrorPage(w, r, http.StatusForbidden, "form_expired", "form_expired_message")
		return ""
	}

	// Verify CSRF token
	expected := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) != 1 {
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return ""
	}

	// Refresh session cookie
	s.setSessionCookie(w, username, s.getSessionRole(r))

	return username
}

// handleBulkApprove approves a pending challenge from the dashboard.
// POST /api/challenges/approve
func (s *Server) handleBulkApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	challengeID := r.FormValue("challenge_id")
	if challengeID == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}

	// Verify the challenge exists and belongs to this user (or user is admin)
	challenge, ok := s.store.Get(challengeID)
	if !ok || challenge.Status != StatusPending {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}
	if challenge.Username != username && s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	// Enforce admin-approval policy: only admins may approve policy-protected hosts.
	if s.requiresAdminApproval(challenge.Hostname) && s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "admin_approval_required")
		return
	}

	// Approve the challenge
	if err := s.store.Approve(challengeID, username); err != nil {
		revokeErrorPage(w, r, http.StatusInternalServerError, "approval_failed", "approval_failed_message")
		return
	}

	challengesApproved.Inc()
	activeChallenges.Dec()
	challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
	log.Printf("BULK_APPROVED: sudo for user %q on host %q (challenge %s) from %s", challenge.Username, challenge.Hostname, challengeID[:8], remoteAddr(r))

	// Log the action
	hostname := challenge.Hostname
	if hostname == "" {
		hostname = "(unknown)"
	}
	s.store.LogAction(challenge.Username, "approved", hostname, challenge.UserCode, username)
	s.broadcastSSE(challenge.Username, "challenge_resolved")

	// Redirect back to the dashboard with flash cookie
	setFlashCookie(w, "approved:"+hostname)
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
}

// handleOneTap processes a one-tap approval link from a notification.
// GET /api/onetap/{token}
func (s *Server) handleOneTap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/api/onetap/")
	if token == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}

	// Parse token: challenge_id.expires_unix.hmac_hex
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	challengeID, expiresStr, providedHMAC := parts[0], parts[1], parts[2]

	// Validate challenge ID format
	if len(challengeID) != 32 {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Check expiry
	expiresUnix, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || time.Now().Unix() > expiresUnix {
		revokeErrorPage(w, r, http.StatusGone, "challenge_expired_or_resolved", "challenge_expired_or_resolved")
		return
	}

	// Verify HMAC
	mac := hmac.New(sha256.New, []byte(s.cfg.SharedSecret))
	mac.Write([]byte("onetap:" + challengeID + ":" + expiresStr))
	expectedHMAC := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expectedHMAC), []byte(providedHMAC)) != 1 {
		log.Printf("SECURITY: invalid one-tap token from %s", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return
	}

	// Get challenge and verify it's still pending (before consuming the one-tap token,
	// so a stale-OIDC redirect doesn't permanently burn the single-use token).
	challenge, ok := s.store.Get(challengeID)
	if !ok || challenge.Status != StatusPending {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	// Admin-approval-required hosts cannot be approved via one-tap — there is no
	// session to verify admin role. The user must approve through the dashboard.
	if s.requiresAdminApproval(challenge.Hostname) {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "admin_approval_required")
		return
	}

	// Check OIDC freshness. If the user's last OIDC login is too old (or never
	// recorded), redirect to OIDC login and carry the token in a short-lived
	// cookie so we can resume here after authentication.
	lastAuth := s.store.LastOIDCAuth(challenge.Username)
	oidcFresh := !lastAuth.IsZero() && time.Since(lastAuth) < s.cfg.OneTapMaxAge
	if !oidcFresh {
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_onetap",
			Value:    token,
			Path:     "/",
			MaxAge:   300, // 5 minutes
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		loginURL := strings.TrimRight(s.cfg.ExternalURL, "/") + "/sessions/login"
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	// OIDC is fresh — consume the single-use token and approve.
	if err := s.store.ConsumeOneTap(challengeID); err != nil {
		revokeErrorPage(w, r, http.StatusConflict, "challenge_expired_or_resolved", "challenge_expired_or_resolved")
		return
	}

	// Approve the challenge
	if err := s.store.Approve(challengeID, challenge.Username); err != nil {
		revokeErrorPage(w, r, http.StatusInternalServerError, "approval_failed", "approval_failed_message")
		return
	}

	challengesApproved.Inc()
	activeChallenges.Dec()
	challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
	hostname := challenge.Hostname
	if hostname == "" {
		hostname = "(unknown)"
	}
	s.store.LogAction(challenge.Username, "approved", hostname, challenge.UserCode, challenge.Username)
	log.Printf("ONETAP_APPROVED: sudo for user %q on host %q (challenge %s) from %s", challenge.Username, hostname, challengeID[:8], remoteAddr(r))

	// Render a simple success page
	w.Header().Set("Content-Type", "text/html")
	lang := detectLanguage(r)
	t := T(lang)
	theme := getTheme(r)
	themeClass := ""
	if theme == "dark" {
		themeClass = ` class="theme-dark"`
	} else if theme == "light" {
		themeClass = ` class="theme-light"`
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="%s"%s>
<head>
  <title>%s</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>%s
    .icon-success { background: var(--success-bg); border: 2px solid var(--success-border); color: var(--success); }
    h2 { color: var(--success); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-success" aria-hidden="true">&#x2713;</div>
    <h2>%s</h2>
    <p>%s %s</p>
    <p style="margin-top:16px"><a href="/" style="color:var(--primary);text-decoration:underline">%s</a></p>
  </div>
</body>
</html>`, lang, themeClass, t("terminal_approved"), sharedCSS,
		t("terminal_approved"),
		t("approved_sudo_on"), template.HTMLEscapeString(hostname),
		t("back_to_dashboard"))
}

// revokeErrorPage renders a styled error page for revoke failures.
// titleKey and messageKey are i18n translation keys.
func revokeErrorPage(w http.ResponseWriter, r *http.Request, status int, titleKey, messageKey string) {
	lang := detectLanguage(r)
	t := T(lang)
	theme := getTheme(r)
	title := t(titleKey)
	message := t(messageKey)
	themeClass := ""
	if theme == "dark" {
		themeClass = ` class="theme-dark"`
	} else if theme == "light" {
		themeClass = ` class="theme-light"`
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	io.WriteString(w, `<!DOCTYPE html>
<html lang="`+lang+`"`+themeClass+`>
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
    <p style="margin-top:16px"><a href="/" style="color:var(--primary);text-decoration:underline">`+template.HTMLEscapeString(t("back_to_dashboard"))+`</a></p>
  </div>
</body>
</html>`)
}

// revokeErrorPageWithLink renders a styled error page with an optional action link.
// titleKey, messageKey, and linkTextKey are i18n translation keys.
func revokeErrorPageWithLink(w http.ResponseWriter, r *http.Request, status int, titleKey, messageKey, linkURL, linkTextKey string) {
	lang := detectLanguage(r)
	t := T(lang)
	theme := getTheme(r)
	title := t(titleKey)
	message := t(messageKey)
	linkText := t(linkTextKey)
	themeClass := ""
	if theme == "dark" {
		themeClass = ` class="theme-dark"`
	} else if theme == "light" {
		themeClass = ` class="theme-light"`
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	linkHTML := ""
	if linkURL != "" && linkText != "" {
		linkHTML = `<p style="margin-top:16px"><a href="` + template.HTMLEscapeString(linkURL) + `" style="color:var(--primary);text-decoration:underline;font-weight:600">` + template.HTMLEscapeString(linkText) + `</a></p>`
	}
	io.WriteString(w, `<!DOCTYPE html>
<html lang="`+lang+`"`+themeClass+`>
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
    <p>`+template.HTMLEscapeString(message)+`</p>`+linkHTML+`
    <p style="margin-top:16px"><a href="/" style="color:var(--primary);text-decoration:underline">`+template.HTMLEscapeString(t("back_to_dashboard"))+`</a></p>
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

	actor := s.verifyFormAuth(w, r)
	if actor == "" {
		return
	}
	sessionOwner := actor

	// Admin may revoke another user's session via a "session_username" form field.
	targetUsername := r.FormValue("session_username")
	if targetUsername != "" && s.getSessionRole(r) == "admin" {
		if !validUsername.MatchString(targetUsername) {
			revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_username_format")
			return
		}
		sessionOwner = targetUsername
	}

	displayHostname := r.FormValue("hostname")
	hostname := displayHostname
	if hostname == "(unknown)" {
		hostname = ""
	} else if hostname == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	} else if !validHostname.MatchString(hostname) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	s.store.RevokeSession(sessionOwner, hostname)
	log.Printf("SESSION_REVOKED: user %q host %q from %s", sessionOwner, hostname, remoteAddr(r))

	// Log the action
	s.store.LogAction(sessionOwner, "revoked", displayHostname, "", actor)
	s.broadcastSSE(sessionOwner, "session_changed")

	// Redirect back to the referring page with flash cookie
	dest := r.FormValue("from")
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/"
	}
	setFlashCookie(w, "revoked:"+displayHostname)
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+dest, http.StatusSeeOther)
}

// handleBulkApproveAll approves all pending challenges for the authenticated user.
// POST /api/challenges/approve-all
func (s *Server) handleBulkApproveAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	// Approve all pending challenges for this user
	pending := s.store.PendingChallenges(username)
	isAdmin := s.getSessionRole(r) == "admin"
	count := 0
	for _, c := range pending {
		// Skip admin-approval-required challenges if the approver is not an admin.
		if s.requiresAdminApproval(c.Hostname) && !isAdmin {
			continue
		}
		if err := s.store.Approve(c.ID, username); err == nil {
			challengesApproved.Inc()
			activeChallenges.Dec()
			challengeDuration.Observe(time.Since(c.CreatedAt).Seconds())
			hostname := c.Hostname
			if hostname == "" {
				hostname = "(unknown)"
			}
			s.store.LogAction(username, "approved", hostname, c.UserCode, username)
			count++
			log.Printf("BULK_APPROVE_ALL: sudo for user %q on host %q (challenge %s) from %s", c.Username, c.Hostname, c.ID[:8], remoteAddr(r))
		}
	}

	s.broadcastSSE(username, "challenge_resolved")
	setFlashCookie(w, fmt.Sprintf("approved_all:%d", count))
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
}

// handleRevokeAll revokes all active sessions for the authenticated user.
// POST /api/sessions/revoke-all
func (s *Server) handleRevokeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	// Revoke all active sessions for this user
	sessions := s.store.ActiveSessions(username)
	count := 0
	for _, sess := range sessions {
		hostname := sess.Hostname
		if hostname == "(unknown)" {
			hostname = ""
		}
		s.store.RevokeSession(username, hostname)
		s.store.LogAction(username, "revoked", sess.Hostname, "", username)
		count++
		log.Printf("BULK_REVOKE_ALL: user %q host %q from %s", username, sess.Hostname, remoteAddr(r))
	}

	s.broadcastSSE(username, "session_changed")
	setFlashCookie(w, fmt.Sprintf("revoked_all:%d", count))
	dest := r.FormValue("from")
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/"
	}
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+dest, http.StatusSeeOther)
}

// handleExtendSession extends an active grace session to the maximum allowed duration.
// POST /api/sessions/extend
func (s *Server) handleExtendSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}
	hostname := r.FormValue("hostname")
	if hostname == "(unknown)" {
		hostname = ""
	} else if hostname == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	} else if !validHostname.MatchString(hostname) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	remaining := s.store.ExtendGraceSession(username, hostname)
	if remaining == 0 {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	displayHostname := hostname
	if displayHostname == "" {
		displayHostname = "(unknown)"
	}
	s.store.LogAction(username, "extended", displayHostname, "", username)
	log.Printf("EXTENDED: user %q host %q to %s from %s", username, displayHostname, remaining, remoteAddr(r))
	s.broadcastSSE(username, "session_changed")

	dest := r.FormValue("from")
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/"
	}
	setFlashCookie(w, "extended:"+displayHostname)
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+dest, http.StatusSeeOther)
}

// handleExtendAll extends all active sessions for the authenticated user to the maximum duration.
// POST /api/sessions/extend-all
func (s *Server) handleExtendAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}
	sessions := s.store.ActiveSessions(username)
	count := 0
	for _, sess := range sessions {
		hostname := sess.Hostname
		if hostname == "(unknown)" {
			hostname = ""
		}
		if s.store.ExtendGraceSession(username, hostname) > 0 {
			s.store.LogAction(username, "extended", sess.Hostname, "", username)
			count++
		}
	}
	log.Printf("BULK_EXTEND_ALL: user %q extended %d sessions from %s", username, count, remoteAddr(r))
	s.broadcastSSE(username, "session_changed")

	setFlashCookie(w, fmt.Sprintf("extended_all:%d", count))
	dest := r.FormValue("from")
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/"
	}
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+dest, http.StatusSeeOther)
}

// handleRejectChallenge rejects a pending challenge from the dashboard.
// POST /api/challenges/reject
func (s *Server) handleRejectChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	challengeID := r.FormValue("challenge_id")
	if challengeID == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}

	// Verify the challenge exists and belongs to this user (or user is admin)
	challenge, ok := s.store.Get(challengeID)
	if !ok || challenge.Status != StatusPending {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}
	if challenge.Username != username && s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	// Deny the challenge
	if err := s.store.Deny(challengeID); err != nil {
		revokeErrorPage(w, r, http.StatusInternalServerError, "rejection_failed", "rejection_failed_message")
		return
	}

	challengesDenied.WithLabelValues("user_rejected").Inc()
	activeChallenges.Dec()
	challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
	hostname := challenge.Hostname
	if hostname == "" {
		hostname = "(unknown)"
	}
	log.Printf("REJECTED: sudo for user %q on host %q (challenge %s) from %s", challenge.Username, hostname, challengeID[:8], remoteAddr(r))
	s.store.LogAction(challenge.Username, "rejected", hostname, challenge.UserCode, username)
	s.broadcastSSE(challenge.Username, "challenge_resolved")

	setFlashCookie(w, "rejected:"+hostname)
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
}

// handleRejectAll rejects all pending challenges for the authenticated user.
// POST /api/challenges/reject-all
func (s *Server) handleRejectAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	// Reject all pending challenges for this user
	pending := s.store.PendingChallenges(username)
	count := 0
	for _, c := range pending {
		if err := s.store.Deny(c.ID); err == nil {
			challengesDenied.WithLabelValues("user_rejected").Inc()
			activeChallenges.Dec()
			challengeDuration.Observe(time.Since(c.CreatedAt).Seconds())
			hostname := c.Hostname
			if hostname == "" {
				hostname = "(unknown)"
			}
			s.store.LogAction(username, "rejected", hostname, c.UserCode, username)
			count++
			log.Printf("BULK_REJECT_ALL: sudo for user %q on host %q (challenge %s) from %s", c.Username, c.Hostname, c.ID[:8], remoteAddr(r))
		}
	}

	s.broadcastSSE(username, "challenge_resolved")
	setFlashCookie(w, fmt.Sprintf("rejected_all:%d", count))
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
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

// sessionsTokenTTL is kept for backward compatibility with CSRF tokens.
const sessionsTokenTTL = 30 * time.Minute

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
	if len(s.sessionNonces) > 1000 {
		s.sessionNonceMu.Unlock()
		http.Error(w, "too many requests — try again later", http.StatusTooManyRequests)
		return
	}
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
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "auth_state_malformed")
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
		revokeErrorPage(w, r, http.StatusBadRequest, "session_expired", "login_session_expired")
		return
	}

	// Check for IdP error
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Printf("OIDC error during sessions login from %s: %s", remoteAddr(r), sanitizeForTerminal(errParam))
		loginURL := strings.TrimRight(s.cfg.ExternalURL, "/") + "/sessions/login"
		revokeErrorPageWithLink(w, r, http.StatusForbidden, "auth_failed", "idp_auth_incomplete", loginURL, "try_again")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_auth_code")
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

	exchangeStart := time.Now()
	token, err := s.oidcConfig.Exchange(exchangeCtx, code)
	oidcExchangeDuration.Observe(time.Since(exchangeStart).Seconds())
	if err != nil {
		log.Printf("ERROR: sessions callback token exchange failed from %s", remoteAddr(r))
		challengesDenied.WithLabelValues("oidc_error").Inc()
		revokeErrorPage(w, r, http.StatusInternalServerError, "auth_failed", "token_exchange_failed")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Printf("ERROR: sessions callback no id_token from %s", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusInternalServerError, "auth_failed", "no_id_token")
		return
	}

	idToken, err := s.verifier.Verify(exchangeCtx, rawIDToken)
	if err != nil {
		log.Printf("ERROR: sessions callback token verification failed from %s", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusInternalServerError, "auth_failed", "token_verify_failed")
		return
	}

	// Verify OIDC nonce
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(stateNonce)) != 1 {
		log.Printf("SECURITY: sessions callback nonce mismatch from %s", remoteAddr(r))
		challengesDenied.WithLabelValues("nonce_mismatch").Inc()
		revokeErrorPage(w, r, http.StatusBadRequest, "auth_failed", "nonce_mismatch")
		return
	}

	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		Picture           string   `json:"picture"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("ERROR: sessions callback claims parsing failed from %s", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusInternalServerError, "auth_failed", "claims_parse_failed")
		return
	}

	username := claims.PreferredUsername
	if username == "" || !validUsername.MatchString(username) {
		log.Printf("SECURITY: sessions callback invalid username from %s", remoteAddr(r))
		challengesDenied.WithLabelValues("identity_mismatch").Inc()
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_identity", "invalid_idp_username")
		return
	}

	// Determine role based on group membership
	role := "user"
	if len(s.cfg.AdminGroups) > 0 {
		for _, userGroup := range claims.Groups {
			for _, adminGroup := range s.cfg.AdminGroups {
				if userGroup == adminGroup {
					role = "admin"
					break
				}
			}
			if role == "admin" {
				break
			}
		}
	}

	log.Printf("SESSIONS: user %q (role=%s) viewed sessions from %s", username, role, remoteAddr(r))

	// Record OIDC authentication time for one-tap freshness checks.
	s.store.RecordOIDCAuth(username)

	// Set session cookie and avatar cookie, then redirect to dashboard.
	s.setSessionCookie(w, username, role)
	if claims.Picture != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_avatar",
			Value:    claims.Picture,
			Path:     "/",
			MaxAge:   1800,
			HttpOnly: false, // needs to be readable for display
			SameSite: http.SameSiteLaxMode,
		})
	}

	// Check for pending one-tap approval after OIDC login.
	// If the pam_onetap cookie is present, the user was redirected here from
	// handleOneTap because their OIDC auth was stale. Now that they've
	// re-authenticated, resume the one-tap approval flow.
	if onetapCookie, err := r.Cookie("pam_onetap"); err == nil && onetapCookie.Value != "" {
		// Clear the cookie
		http.SetCookie(w, &http.Cookie{Name: "pam_onetap", Value: "", Path: "/", MaxAge: -1})
		// Redirect back to the one-tap endpoint — freshness check will now pass
		onetapURL := strings.TrimRight(s.cfg.ExternalURL, "/") + "/api/onetap/" + onetapCookie.Value
		http.Redirect(w, r, onetapURL, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
}


// handleHistoryPage renders the full action history with search and filter.
// GET /history
func (s *Server) handleHistoryPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)

	username := s.getSessionUser(r)
	if username == "" {
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

	// Timezone handling: set cookie if tz param provided, then read from cookie
	tzName := "UTC"
	if tzParam := r.URL.Query().Get("tz"); tzParam != "" {
		if loc, err := time.LoadLocation(tzParam); err == nil {
			_ = loc
			tzName = tzParam
			http.SetCookie(w, &http.Cookie{
				Name:     "pam_tz",
				Value:    tzParam,
				Path:     "/",
				MaxAge:   86400,
				HttpOnly: false, // must be readable by JS for auto-detection
				SameSite: http.SameSiteLaxMode,
			})
		}
	} else if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if loc, err := time.LoadLocation(c.Value); err == nil {
			_ = loc
			tzName = c.Value
		}
	}
	tzLoc, _ := time.LoadLocation(tzName)

	query := r.URL.Query().Get("q")
	actionFilter := r.URL.Query().Get("action")
	hostFilter := r.URL.Query().Get("hostname")

	// Parse sort and order params
	sortField := r.URL.Query().Get("sort")
	switch sortField {
	case "timestamp", "action", "hostname", "code":
		// valid
	default:
		sortField = "timestamp"
	}
	sortOrder := r.URL.Query().Get("order")
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}

	// Parse per_page with validation
	perPage := s.cfg.DefaultHistoryPageSize
	if pp, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil {
		validSizes := map[int]bool{5: true, 10: true, 25: true, 50: true, 100: true, 500: true, 1000: true}
		if validSizes[pp] {
			perPage = pp
		}
	}

	allHistory := s.store.ActionHistory(username)

	// Collect unique action types and hostnames from the FULL unfiltered history
	actionSet := make(map[string]bool)
	hostSet := make(map[string]bool)
	for _, e := range allHistory {
		actionSet[e.Action] = true
		if e.Hostname != "" {
			hostSet[e.Hostname] = true
		}
	}

	// Build ActionOptions
	t := T(lang)
	var actionOptions []ActionOption
	actionOrder := []string{"approved", "auto_approved", "rejected", "revoked", "elevated", "extended", "rotated_breakglass"}
	for _, a := range actionOrder {
		if actionSet[a] {
			actionOptions = append(actionOptions, ActionOption{Value: a, Label: t(a)})
		}
	}
	// Include any action types not in the predefined order
	for a := range actionSet {
		found := false
		for _, known := range actionOrder {
			if a == known {
				found = true
				break
			}
		}
		if !found {
			actionOptions = append(actionOptions, ActionOption{Value: a, Label: t(a)})
		}
	}

	// Build sorted HostOptions
	var hostOptions []string
	for h := range hostSet {
		hostOptions = append(hostOptions, h)
	}
	sort.Strings(hostOptions)

	// Build 24-hour activity timeline from the full unfiltered history.
	// This always shows the complete 24h view so users can see the overall pattern.
	nowInTZ := time.Now().In(tzLoc)
	var timeline []timelineEntry
	activeHoursAgo := -1 // which bar is currently active (-1 = none)
	for i := 23; i >= 0; i-- {
		hourInTZ := nowInTZ.Add(-time.Duration(i+1) * time.Hour)
		hourStart := hourInTZ.Truncate(time.Hour)
		hourEnd := hourStart.Add(time.Hour)
		hoursAgo := i // bar at i=0 is the current (most recent) hour

		count := 0
		actionCounts := make(map[string][]string) // action -> hostnames
		for _, e := range allHistory {
			if e.Timestamp.After(hourStart) && e.Timestamp.Before(hourEnd) {
				count++
				actionCounts[e.Action] = append(actionCounts[e.Action], e.Hostname)
			}
		}

		// Build rich tooltip text
		var detailParts []string
		detailParts = append(detailParts, fmt.Sprintf("%d:00 – %d:00", hourStart.Hour(), hourEnd.Hour()))
		// Sort action keys for deterministic ordering
		var actionKeys []string
		for a := range actionCounts {
			actionKeys = append(actionKeys, a)
		}
		sort.Strings(actionKeys)
		for _, action := range actionKeys {
			hosts := actionCounts[action]
			// Deduplicate hosts
			seen := make(map[string]bool)
			var unique []string
			for _, h := range hosts {
				if h != "" && !seen[h] {
					seen[h] = true
					unique = append(unique, h)
				}
			}
			sort.Strings(unique)
			hostStr := strings.Join(unique, ", ")
			if hostStr != "" {
				detailParts = append(detailParts, fmt.Sprintf("%d %s (%s)", len(hosts), t(action), hostStr))
			} else {
				detailParts = append(detailParts, fmt.Sprintf("%d %s", len(hosts), t(action)))
			}
		}

		height := 2
		if count > 0 {
			height = count * 8
			if height > 40 {
				height = 40
			}
		}
		timeline = append(timeline, timelineEntry{
			Hour:      hourStart.Hour(),
			HourLabel: fmt.Sprintf("%d:00", hourStart.Hour()),
			Count:     count,
			Height:    height,
			IsNow:     i == 0,
			HoursAgo:  hoursAgo,
			Details:   strings.Join(detailParts, "\n"),
		})
	}

	// Parse hours_ago filter (applied before other filters so they can combine)
	hoursAgoStr := r.URL.Query().Get("hours_ago")
	if hoursAgoStr != "" {
		if h, err := strconv.Atoi(hoursAgoStr); err == nil && h >= 0 && h < 24 {
			activeHoursAgo = h
			hourStart := nowInTZ.Add(-time.Duration(h+1) * time.Hour).Truncate(time.Hour)
			hourEnd := hourStart.Add(time.Hour)
			var filtered []ActionLogEntry
			for _, e := range allHistory {
				if e.Timestamp.After(hourStart) && e.Timestamp.Before(hourEnd) {
					filtered = append(filtered, e)
				}
			}
			allHistory = filtered
		}
	}

	history := allHistory

	// Filter by action type
	if actionFilter != "" {
		var filtered []ActionLogEntry
		for _, e := range history {
			if e.Action == actionFilter {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Filter by hostname
	if hostFilter != "" {
		var filtered []ActionLogEntry
		for _, e := range history {
			if e.Hostname == hostFilter {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Filter by search term (case-insensitive match on hostname or code)
	if query != "" {
		q := strings.ToLower(query)
		var filtered []ActionLogEntry
		for _, e := range history {
			if strings.Contains(strings.ToLower(e.Hostname), q) || strings.Contains(strings.ToLower(e.Code), q) {
				filtered = append(filtered, e)
			}
		}
		history = filtered
	}

	// Sort results
	asc := sortOrder == "asc"
	sort.SliceStable(history, func(i, j int) bool {
		switch sortField {
		case "action":
			if asc {
				return history[i].Action < history[j].Action
			}
			return history[i].Action > history[j].Action
		case "hostname":
			if asc {
				return history[i].Hostname < history[j].Hostname
			}
			return history[i].Hostname > history[j].Hostname
		case "code":
			if asc {
				return history[i].Code < history[j].Code
			}
			return history[i].Code > history[j].Code
		default: // timestamp
			if asc {
				return history[i].Timestamp.Before(history[j].Timestamp)
			}
			return history[i].Timestamp.After(history[j].Timestamp)
		}
	})

	// Paginate
	totalPages := (len(history) + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * perPage
	end := start + perPage
	if end > len(history) {
		end = len(history)
	}
	pageHistory := history[start:end]

	// Pre-format entries with timezone
	var viewEntries []historyViewEntry
	for _, e := range pageHistory {
		viewEntries = append(viewEntries, historyViewEntry{
			Action:        e.Action,
			ActionLabel:   t(e.Action),
			Hostname:      e.Hostname,
			Code:          e.Code,
			Actor:         e.Actor,
			FormattedTime: e.Timestamp.In(tzLoc).Format("2006-01-02 15:04"),
			TimeAgo:       timeAgoI18n(e.Timestamp, t),
		})
	}

	perPageOptions := []int{5, 10, 25, 50, 100, 500, 1000}

	w.Header().Set("Content-Type", "text/html")
	if err := historyTmpl.Execute(w, map[string]interface{}{
		"Username":        username,
		"Initial":         strings.ToUpper(username[:1]),
		"Avatar":          getAvatar(r),
		"History":         viewEntries,
		"Query":           query,
		"ActionFilter":    actionFilter,
		"HostFilter":      hostFilter,
		"ActionOptions":   actionOptions,
		"HostOptions":     hostOptions,
		"ActivePage":      "history",
		"Theme":           getTheme(r),
		"Page":            page,
		"TotalPages":      totalPages,
		"HasPrev":         page > 1,
		"HasNext":         page < totalPages,
		"Sort":            sortField,
		"Order":           sortOrder,
		"PerPage":         perPage,
		"PerPageOptions":  perPageOptions,
		"TZName":          tzName,
		"Timezone":        tzName,
		"CSPNonce":        r.Context().Value("csp-nonce"),
		"T":               T(lang),
		"Lang":            lang,
		"Languages":       supportedLanguages,
		"Timeline":        timeline,
		"HoursAgo":        hoursAgoStr,
		"ActiveHoursAgo":  activeHoursAgo,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

// handleHistoryExport exports action history as CSV or JSON.
// Session-authenticated users see their own history.
// API key callers (Authorization: Bearer <key>) see all users' combined history.
// GET /api/history/export?format=csv|json
func (s *Server) handleHistoryExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.getSessionUser(r)
	apiKeyAccess := false
	if username == "" {
		if !s.verifyAPIKey(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// API key access — export ALL users' history (admin-level)
		apiKeyAccess = true
	}

	format := r.URL.Query().Get("format")

	if apiKeyAccess {
		// Return all-users history with username field included.
		allHistory := s.store.AllActionHistoryWithUsers()
		switch format {
		case "csv":
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=pam-pocketid-history.csv")
			w.Write([]byte("username,timestamp,action,hostname,code,actor\n"))
			for _, e := range allHistory {
				fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s\n",
					e.Username,
					e.Timestamp.Format(time.RFC3339),
					e.Action,
					e.Hostname,
					e.Code,
					e.Actor)
			}
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=pam-pocketid-history.json")
			json.NewEncoder(w).Encode(allHistory)
		default:
			http.Error(w, "format must be csv or json", http.StatusBadRequest)
		}
		return
	}

	// Session-based access: export the authenticated user's own history.
	history := s.store.ActionHistory(username)
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=pam-pocketid-history.csv")
		w.Write([]byte("timestamp,action,hostname,code,actor\n"))
		for _, e := range history {
			fmt.Fprintf(w, "%s,%s,%s,%s,%s\n",
				e.Timestamp.Format(time.RFC3339),
				e.Action,
				e.Hostname,
				e.Code,
				e.Actor)
		}
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=pam-pocketid-history.json")
		json.NewEncoder(w).Encode(history)
	default:
		http.Error(w, "format must be csv or json", http.StatusBadRequest)
	}
}

// handleHostsPage renders the known hosts page with grace status and elevate controls.
// GET /hosts
func (s *Server) handleHostsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

	// Parse flash messages from cookie
	var flashes []string
	if flashParam := getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) == 2 {
				switch parts[0] {
				case "elevated":
					flashes = append(flashes, t("elevated_session_on")+" "+parts[1])
				case "extended":
					flashes = append(flashes, t("extended_session_on")+" "+parts[1])
				case "extended_all":
					flashes = append(flashes, fmt.Sprintf(t("extended_n_sessions"), atoi(parts[1])))
				case "revoked":
					flashes = append(flashes, t("revoked_session_on")+" "+parts[1])
				case "revoked_all":
					flashes = append(flashes, fmt.Sprintf(t("revoked_n_sessions"), atoi(parts[1])))
				case "rotated":
					flashes = append(flashes, t("rotated_breakglass_on")+" "+parts[1])
				case "rotated_all":
					flashes = append(flashes, fmt.Sprintf(t("rotated_n_hosts"), atoi(parts[1])))
				}
			}
		}
	}

	hosts := s.store.KnownHosts(username)
	escrowed := s.store.EscrowedHosts()

	// Merge escrowed hosts into the known hosts list
	escrowedSet := make(map[string]bool)
	for h := range escrowed {
		// Skip escrowed hosts the user is not authorized for
		if s.hostRegistry.IsEnabled() && !s.hostRegistry.IsUserAuthorized(h, username) {
			continue
		}
		escrowedSet[h] = true
		// Add escrowed hosts that aren't already known from action history
		found := false
		for _, kh := range hosts {
			if kh == h {
				found = true
				break
			}
		}
		if !found {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)

	// Default rotation days for escrow validity
	rotationDays := 90
	if s.cfg.ClientBreakglassRotationDays > 0 {
		rotationDays = s.cfg.ClientBreakglassRotationDays
	}

	// Merge registered hosts into the known hosts list
	if s.hostRegistry.IsEnabled() {
		for _, rh := range s.hostRegistry.HostsForUser(username) {
			found := false
			for _, kh := range hosts {
				if kh == rh {
					found = true
					break
				}
			}
			if !found {
				hosts = append(hosts, rh)
			}
		}
		sort.Strings(hosts)
	}

	type hostView struct {
		Hostname        string
		Active          bool
		Remaining       string
		Escrowed        bool
		EscrowAge       string
		EscrowExpired   bool
		EscrowLink      string
		Registered      bool
		AuthorizedUsers []string
		Group           string
	}

	// Collect all group names for the filter dropdown
	groupFilter := r.URL.Query().Get("group")
	groupSet := make(map[string]struct{})

	var hostViews []hostView
	for _, h := range hosts {
		rem := s.store.GraceRemaining(username, h)
		hv := hostView{Hostname: h}
		if rem > 0 {
			hv.Active = true
			hv.Remaining = formatDuration(rem)
		}
		if escrowRecord, ok := escrowed[h]; ok {
			hv.Escrowed = true
			hv.EscrowAge = formatDuration(time.Since(escrowRecord.Timestamp))
			hv.EscrowExpired = time.Since(escrowRecord.Timestamp) > time.Duration(rotationDays)*24*time.Hour
			if s.cfg.EscrowLinkTemplate != "" {
				link := strings.ReplaceAll(s.cfg.EscrowLinkTemplate, "{hostname}", h)
				if escrowRecord.ItemID != "" {
					link = strings.ReplaceAll(link, "{item_id}", escrowRecord.ItemID)
				}
				hv.EscrowLink = link
			}
		}
		if users, group, _, ok := s.hostRegistry.GetHost(h); ok {
			hv.Registered = true
			hv.AuthorizedUsers = users
			hv.Group = group
		}
		if hv.Group != "" {
			groupSet[hv.Group] = struct{}{}
		}
		// Apply group filter if set
		if groupFilter != "" && hv.Group != groupFilter {
			continue
		}
		hostViews = append(hostViews, hv)
	}

	// Build sorted list of all known groups for the filter dropdown
	var allGroups []string
	for g := range groupSet {
		allGroups = append(allGroups, g)
	}
	sort.Strings(allGroups)

	now := time.Now()
	csrfTs := fmt.Sprintf("%d", now.Unix())
	csrfToken := computeCSRFToken(s.cfg.SharedSecret, username, csrfTs)

	// Build duration options, filtering to those <= GracePeriod
	type durationOption struct {
		Value    int
		Label    string
		Selected bool
	}
	allDurations := []durationOption{
		{3600, t("1_hour"), false},
		{14400, t("4_hours"), false},
		{28800, t("8_hours"), true},
		{86400, t("1_day"), false},
	}
	var durations []durationOption
	graceSec := int(s.cfg.GracePeriod.Seconds())
	if graceSec <= 0 {
		graceSec = 86400 // default cap if grace period is not configured
	}
	for _, d := range allDurations {
		if d.Value <= graceSec {
			d.Selected = false // reset
			durations = append(durations, d)
		}
	}
	if len(durations) > 0 {
		durations[len(durations)-1].Selected = true
	}
	// If no durations fit (GracePeriod < 1h), add a single option for the configured grace period
	if len(durations) == 0 && s.cfg.GracePeriod > 0 {
		durations = append(durations, durationOption{
			Value:    int(s.cfg.GracePeriod.Seconds()),
			Label:    formatDuration(s.cfg.GracePeriod),
			Selected: true,
		})
	}

	// Read timezone from cookie for profile dropdown display
	hostsTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			hostsTZ = c.Value
		}
	}

	hasEscrowed := false
	for _, hv := range hostViews {
		if hv.Escrowed {
			hasEscrowed = true
			break
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := hostsTmpl.Execute(w, map[string]interface{}{
		"Username":         username,
		"Initial":          strings.ToUpper(username[:1]),
		"Avatar":           getAvatar(r),
		"Timezone":         hostsTZ,
		"Flashes":          flashes,
		"Hosts":            hostViews,
		"CSRFToken":        csrfToken,
		"CSRFTs":           csrfTs,
		"Durations":        durations,
		"ActivePage":       "hosts",
		"Theme":            getTheme(r),
		"CSPNonce":         r.Context().Value("csp-nonce"),
		"T":                T(lang),
		"Lang":             lang,
		"Languages":        supportedLanguages,
		"EscrowLinkLabel":  s.cfg.EscrowLinkLabel,
		"HasEscrowedHosts": hasEscrowed,
		"AllGroups":        allGroups,
		"GroupFilter":      groupFilter,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

// handleElevate creates a grace session for a host manually.
// POST /api/hosts/elevate
func (s *Server) handleElevate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	hostname := r.FormValue("hostname")
	durationStr := r.FormValue("duration")
	if hostname == "" || durationStr == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}
	if !validHostname.MatchString(hostname) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Verify user is authorized for this host
	if s.hostRegistry.IsEnabled() && !s.hostRegistry.IsUserAuthorized(hostname, username) {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}

	// Parse and clamp duration
	durationSec, err := strconv.Atoi(durationStr)
	if err != nil || durationSec < 1 {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_duration")
		return
	}
	duration := time.Duration(durationSec) * time.Second
	// Clamp to [1h, GracePeriod]
	if duration < 1*time.Hour {
		duration = 1 * time.Hour
	}
	if s.cfg.GracePeriod > 0 && duration > s.cfg.GracePeriod {
		duration = s.cfg.GracePeriod
	}
	if duration > 24*time.Hour {
		duration = 24 * time.Hour
	}

	s.store.CreateGraceSession(username, hostname, duration)
	s.store.LogAction(username, "elevated", hostname, "", username)
	log.Printf("ELEVATED: user %q host %q duration %s from %s", username, hostname, duration, remoteAddr(r))
	s.broadcastSSE(username, "session_changed")

	setFlashCookie(w, "elevated:"+hostname)
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/hosts", http.StatusSeeOther)
}

// handleRotateHost requests breakglass rotation for a single host.
// POST /api/hosts/rotate
func (s *Server) handleRotateHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}
	hostname := r.FormValue("hostname")
	if hostname == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}
	if !validHostname.MatchString(hostname) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	s.store.SetHostRotateBefore(hostname)
	s.store.LogAction(username, "rotation_requested", hostname, "", username)
	log.Printf("ROTATE_BREAKGLASS: user %q requested rotation for host %q from %s", username, hostname, remoteAddr(r))
	s.broadcastSSE(username, "host_changed")
	setFlashCookie(w, "rotated:"+hostname)
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/hosts", http.StatusSeeOther)
}

// handleRotateAllHosts requests breakglass rotation for all hosts.
// POST /api/hosts/rotate-all
func (s *Server) handleRotateAllHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}
	// Get all known hosts for this user
	hosts := s.store.KnownHosts(username)
	if s.hostRegistry.IsEnabled() {
		for _, rh := range s.hostRegistry.HostsForUser(username) {
			found := false
			for _, h := range hosts {
				if h == rh {
					found = true
					break
				}
			}
			if !found {
				hosts = append(hosts, rh)
			}
		}
	}
	s.store.SetAllHostsRotateBefore(hosts)
	for _, h := range hosts {
		s.store.LogAction(username, "rotation_requested", h, "", username)
	}
	log.Printf("ROTATE_ALL_BREAKGLASS: user %q requested rotation for %d hosts from %s", username, len(hosts), remoteAddr(r))
	s.broadcastSSE(username, "host_changed")
	setFlashCookie(w, fmt.Sprintf("rotated_all:%d", len(hosts)))
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/hosts", http.StatusSeeOther)
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
	if s.cfg.SharedSecret == "" && !s.hostRegistry.IsEnabled() {
		http.Error(w, "escrow endpoint requires shared secret authentication", http.StatusForbidden)
		return
	}

	if !s.verifyAPISecret(r) {
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

	// Parse item ID from escrow command stdout (format: "item_id=xxx")
	var itemID string
	for _, line := range strings.Split(stdoutBuf.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "item_id=") {
			itemID = strings.TrimPrefix(line, "item_id=")
			break
		}
	}
	s.store.RecordEscrow(req.Hostname, itemID)
	// Log the escrow as a "rotated_breakglass" action visible in the history page.
	// Since escrow is a machine-level operation (no user session), log it for all
	// users who have activity on this host so it appears in their history.
	for _, user := range s.store.UsersWithHostActivity(req.Hostname) {
		s.store.LogAction(user, "rotated_breakglass", req.Hostname, "", "")
	}
	log.Printf("BREAKGLASS: password escrowed for host %q", req.Hostname)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		log.Printf("ERROR: writing JSON response: %v", err)
	}
}

// handleInfoPage renders the server configuration and system info page.
// GET /info
func (s *Server) handleInfoPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle language change via query param
	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		setFlashCookie(w, "expired:")
		http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, username, s.getSessionRole(r))

	// Server configuration values
	gracePeriod := formatDuration(s.cfg.GracePeriod)
	challengeTTL := formatDuration(s.cfg.ChallengeTTL)

	breakglassType := s.cfg.ClientBreakglassPasswordType
	if breakglassType == "" {
		breakglassType = t("not_configured")
	}

	breakglassRotation := t("not_configured")
	if s.cfg.ClientBreakglassRotationDays > 0 {
		breakglassRotation = fmt.Sprintf("%d %s", s.cfg.ClientBreakglassRotationDays, t("days"))
	}

	tokenCache := t("disabled")
	if s.cfg.ClientTokenCacheEnabled != nil && *s.cfg.ClientTokenCacheEnabled {
		tokenCache = t("enabled")
	}

	escrowConfigured := t("not_configured")
	if s.cfg.EscrowCommand != "" {
		escrowConfigured = t("configured")
	}

	notifyConfigured := t("not_configured")
	if s.cfg.NotifyCommand != "" {
		notifyConfigured = t("configured")
	}

	hostRegistryEnabled := s.hostRegistry.IsEnabled()
	hostRegistryStatus := t("host_registry_global_secret")
	if hostRegistryEnabled {
		hostRegistryStatus = fmt.Sprintf(t("enabled_n_hosts"), len(s.hostRegistry.RegisteredHosts()))
	}

	sessionPersistence := t("disabled")
	if s.cfg.SessionStateFile != "" {
		sessionPersistence = s.cfg.SessionStateFile
	}

	// System info
	uptime := time.Since(serverStartTime)
	uptimeStr := formatDuration(uptime)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	allocMB := float64(memStats.Alloc) / 1024 / 1024
	sysMB := float64(memStats.Sys) / 1024 / 1024
	memUsage := fmt.Sprintf("%.1f MB alloc / %.1f MB sys", allocMB, sysMB)

	// Active grace sessions for the current user
	activeSessions := len(s.store.ActiveSessions(username))

	// Read timezone from cookie for profile dropdown display
	infoTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, err := time.LoadLocation(c.Value); err == nil {
			infoTZ = c.Value
		}
	}

	w.Header().Set("Content-Type", "text/html")
	if err := infoTmpl.Execute(w, map[string]interface{}{
		"Username":            username,
		"Initial":             strings.ToUpper(username[:1]),
		"Avatar":              getAvatar(r),
		"Timezone":            infoTZ,
		"ActivePage":          "info",
		"Theme":               getTheme(r),
		"CSPNonce":            r.Context().Value("csp-nonce"),
		"T":                   T(lang),
		"Lang":                lang,
		"Languages":           supportedLanguages,
		"Version":             version,
		"GracePeriod":         gracePeriod,
		"ChallengeTTL":        challengeTTL,
		"BreakglassType":      breakglassType,
		"BreakglassRotation":  breakglassRotation,
		"TokenCache":          tokenCache,
		"DefaultPageSize":     s.cfg.DefaultHistoryPageSize,
		"EscrowConfigured":    escrowConfigured,
		"NotifyConfigured":    notifyConfigured,
		"HostRegistry":        hostRegistryStatus,
		"SessionPersistence":  sessionPersistence,
		"OneTapMaxAge":        formatDuration(s.cfg.OneTapMaxAge),
		"AdminGroups":         func() string { if len(s.cfg.AdminGroups) == 0 { return t("not_configured") }; return strings.Join(s.cfg.AdminGroups, ", ") }(),
		"AdminApprovalHosts":  func() string { if len(s.cfg.AdminApprovalHosts) == 0 { return t("not_configured") }; return strings.Join(s.cfg.AdminApprovalHosts, ", ") }(),
		"Uptime":              uptimeStr,
		"GoVersion":           runtime.Version(),
		"OSArch":              runtime.GOOS + "/" + runtime.GOARCH,
		"Goroutines":          runtime.NumGoroutine(),
		"MemUsage":            memUsage,
		"ActiveSessionsCount": activeSessions,
	}); err != nil {
		log.Printf("ERROR: template execution: %v", err)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// atoi converts a string to int, returning 0 on error. Used for flash message formatting.
func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
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
    .theme-light {
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
    .theme-dark {
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
      --focus-ring: 0 0 0 3px rgba(96,165,250,0.4);
    }
    *, *::before, *::after { box-sizing: border-box; }
    @media (min-width: 768px) {
      body.wide { max-width: 960px; }
    }
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

// formatTime formats a time as "2006-01-02 15:04 UTC".
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}

// actionLabel maps action strings to human-readable display labels.
func actionLabel(action string) string {
	switch action {
	case "auto_approved":
		return "Auto-approved"
	case "approved":
		return "Approved"
	case "revoked":
		return "Revoked"
	case "rejected":
		return "Rejected"
	case "elevated":
		return "Elevated"
	case "extended":
		return "Extended"
	default:
		return action
	}
}

// timeAgo formats a time as a human-readable relative string like "2m ago" or "1h ago".
func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// timeAgoStr formats a time as a human-readable relative string (non-template version).
func timeAgoStr(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// timeAgoI18n formats a time as a localized human-readable relative string.
func timeAgoI18n(when time.Time, t func(string) string) string {
	d := time.Since(when)
	switch {
	case d < time.Minute:
		return t("just_now")
	case d < time.Hour:
		return fmt.Sprintf("%d%s %s", int(d.Minutes()), t("minute_abbr"), t("ago"))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d%s %s", int(d.Hours()), t("hour_abbr"), t("ago"))
	default:
		return fmt.Sprintf("%d%s %s", int(d.Hours()/24), t("day_abbr"), t("ago"))
	}
}

// actionLabelStr maps action strings to human-readable display labels (non-template version).
func actionLabelStr(action string) string {
	switch action {
	case "auto_approved":
		return "Auto-approved"
	case "approved":
		return "Approved"
	case "revoked":
		return "Revoked"
	case "rejected":
		return "Rejected"
	case "elevated":
		return "Elevated"
	case "extended":
		return "Extended"
	default:
		return action
	}
}

// historyViewEntry is a pre-formatted history entry for the template.
type historyViewEntry struct {
	Action        string
	ActionLabel   string
	Hostname      string
	Code          string
	Actor         string
	FormattedTime string
	TimeAgo       string
}

// timelineEntry represents one hour-slot in the 24-hour activity timeline.
type timelineEntry struct {
	Hour      int
	HourLabel string // "14:00"
	Count     int
	Height    int // bar height in pixels (2-40)
	IsNow     bool
	HoursAgo  int    // offset from now (0 = current hour)
	Details   string // rich tooltip text
}

// ActionOption represents a value/label pair for dropdown select options.
type ActionOption struct {
	Value string
	Label string
}

const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>pam-pocketid</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + `
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
    <h2>pam-pocketid</h2>
    {{range .Flashes}}<div style="background:var(--warning-bg);border:1px solid var(--warning-border);color:var(--warning);padding:10px 16px;border-radius:8px;margin-bottom:12px;font-size:0.875rem;" role="alert">{{.}}</div>{{end}}
    <p>Sign in with Pocket ID to manage your sudo sessions.</p>
    <a href="{{.LoginURL}}" class="btn" role="button">Sign in with Pocket ID</a>
  </div>
</body>
</html>`

// navCSS is the shared navigation bar styles used across dashboard, history, and hosts pages.
const navCSS = `
    .nav { display: flex; gap: 16px; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border); justify-content: center; align-items: center; }
    .nav a { color: var(--text-secondary); text-decoration: none; font-size: 0.875rem; font-weight: 500; padding: 4px 8px; border-radius: 6px; }
    .nav a:hover { color: var(--text); background: var(--info-bg); }
    .nav a.active { color: var(--primary); font-weight: 700; }
    .theme-options { display: flex; gap: 4px; padding: 4px 12px 8px; }
    .theme-option { flex: 1; text-align: center; padding: 4px 8px; border-radius: 6px; font-size: 0.75rem; color: var(--text-secondary); text-decoration: none; border: 1px solid var(--border); cursor: pointer; }
    .theme-option:hover { background: var(--info-bg); color: var(--text); }
    .theme-option.active { background: #2563eb; color: #fff; border-color: #2563eb; font-weight: 600; }
    .profile-menu { position: relative; }
    .profile-btn {
      width: 32px; height: 32px; border-radius: 50%;
      background: var(--primary); color: var(--primary-text);
      display: flex; align-items: center; justify-content: center;
      font-weight: 700; font-size: 0.813rem; cursor: pointer;
      border: none; text-decoration: none;
    }
    .profile-btn:hover { opacity: 0.9; }
    .profile-img { width: 32px; height: 32px; border-radius: 50%; object-fit: cover; }
    .profile-dropdown {
      display: none;
      position: absolute; right: 0; top: 40px;
      background: var(--card-bg); border: 1px solid var(--border);
      border-radius: 10px; box-shadow: var(--shadow);
      min-width: 220px; padding: 12px 0; z-index: 100;
    }
    .profile-menu:focus-within .profile-dropdown { display: block; }
    .profile-dropdown-item {
      display: block; padding: 8px 16px; color: var(--text);
      text-decoration: none; font-size: 0.875rem;
    }
    .profile-dropdown-item:hover { background: var(--info-bg); }
    .profile-dropdown-divider { border-top: 1px solid var(--border); margin: 8px 0; }
    .profile-dropdown-label {
      padding: 4px 16px; font-size: 0.75rem; color: var(--text-secondary);
      font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
    }
    .profile-dropdown select {
      margin: 4px 16px; padding: 4px 8px; border: 1px solid var(--border);
      border-radius: 6px; font-size: 0.813rem; background: var(--card-bg); color: var(--text);
      width: calc(100% - 32px);
    }
`

// tzOptionsHTML is the timezone <option> list reused in the profile dropdown across all pages.
const tzOptionsHTML = `
    <option value="UTC" {{if eq .Timezone "UTC"}}selected{{end}}>UTC</option>
    <optgroup label="Americas">
      <option value="Pacific/Honolulu" {{if eq .Timezone "Pacific/Honolulu"}}selected{{end}}>UTC-10 (Hawaii)</option>
      <option value="America/Anchorage" {{if eq .Timezone "America/Anchorage"}}selected{{end}}>UTC-9 (Alaska)</option>
      <option value="America/Los_Angeles" {{if eq .Timezone "America/Los_Angeles"}}selected{{end}}>UTC-8 (Los Angeles, Vancouver)</option>
      <option value="America/Denver" {{if eq .Timezone "America/Denver"}}selected{{end}}>UTC-7 (Denver, Phoenix)</option>
      <option value="America/Chicago" {{if eq .Timezone "America/Chicago"}}selected{{end}}>UTC-6 (Chicago, Mexico City)</option>
      <option value="America/New_York" {{if eq .Timezone "America/New_York"}}selected{{end}}>UTC-5 (New York, Toronto)</option>
      <option value="America/Halifax" {{if eq .Timezone "America/Halifax"}}selected{{end}}>UTC-4 (Halifax, Bermuda)</option>
      <option value="America/St_Johns" {{if eq .Timezone "America/St_Johns"}}selected{{end}}>UTC-3:30 (Newfoundland)</option>
      <option value="America/Sao_Paulo" {{if eq .Timezone "America/Sao_Paulo"}}selected{{end}}>UTC-3 (São Paulo, Buenos Aires)</option>
    </optgroup>
    <optgroup label="Europe &amp; Africa">
      <option value="Atlantic/Reykjavik" {{if eq .Timezone "Atlantic/Reykjavik"}}selected{{end}}>UTC+0 (Reykjavik)</option>
      <option value="Europe/London" {{if eq .Timezone "Europe/London"}}selected{{end}}>UTC+0 (London, Dublin)</option>
      <option value="Europe/Paris" {{if eq .Timezone "Europe/Paris"}}selected{{end}}>UTC+1 (Paris, Berlin, Amsterdam)</option>
      <option value="Europe/Helsinki" {{if eq .Timezone "Europe/Helsinki"}}selected{{end}}>UTC+2 (Helsinki, Cairo, Johannesburg)</option>
      <option value="Europe/Moscow" {{if eq .Timezone "Europe/Moscow"}}selected{{end}}>UTC+3 (Moscow, Istanbul, Nairobi)</option>
    </optgroup>
    <optgroup label="Asia &amp; Pacific">
      <option value="Asia/Dubai" {{if eq .Timezone "Asia/Dubai"}}selected{{end}}>UTC+4 (Dubai, Baku)</option>
      <option value="Asia/Kolkata" {{if eq .Timezone "Asia/Kolkata"}}selected{{end}}>UTC+5:30 (Mumbai, New Delhi)</option>
      <option value="Asia/Dhaka" {{if eq .Timezone "Asia/Dhaka"}}selected{{end}}>UTC+6 (Dhaka, Almaty)</option>
      <option value="Asia/Bangkok" {{if eq .Timezone "Asia/Bangkok"}}selected{{end}}>UTC+7 (Bangkok, Jakarta)</option>
      <option value="Asia/Shanghai" {{if eq .Timezone "Asia/Shanghai"}}selected{{end}}>UTC+8 (Shanghai, Singapore, Perth)</option>
      <option value="Asia/Tokyo" {{if eq .Timezone "Asia/Tokyo"}}selected{{end}}>UTC+9 (Tokyo, Seoul)</option>
      <option value="Australia/Sydney" {{if eq .Timezone "Australia/Sydney"}}selected{{end}}>UTC+10 (Sydney, Melbourne)</option>
      <option value="Pacific/Auckland" {{if eq .Timezone "Pacific/Auckland"}}selected{{end}}>UTC+12 (Auckland, Fiji)</option>
    </optgroup>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>Sessions - pam-pocketid</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + navCSS + `
    body { align-items: flex-start; padding-top: 32px; }
    .section-label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      margin: 24px 0 8px;
      text-align: left;
    }
    .section-label.pending { color: var(--warning); }
    .list { text-align: left; margin: 0 0 8px; }
    .row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); gap: 12px; }
    .row-info { min-width: 0; flex: 1; }
    .row-host { font-weight: 600; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-sub { color: var(--text-secondary); font-size: 0.813rem; display: block; }
    .row-code { color: var(--text-secondary); font-size: 0.813rem; font-family: monospace; display: block; }
    .banner { padding: 10px 16px; border-radius: 8px; margin-bottom: 12px; font-size: 0.875rem; font-weight: 600; text-align: left; }
    .banner-success { background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }
    .approve-btn { background: var(--success); border: none; color: #fff; padding: 6px 12px; border-radius: 8px; cursor: pointer; font-size: 0.813rem; font-weight: 600; min-height: 32px; white-space: nowrap; flex-shrink: 0; }
    .approve-btn:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(5,150,105,0.4); }
    .approve-btn:hover { opacity: 0.9; }
    .host-btn { display: inline-block; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; font-weight: 600; white-space: nowrap; border: 1px solid var(--border); background: none; color: var(--text-secondary); text-decoration: none; text-align: center; line-height: 1.4; }
    .host-btn:hover { background: var(--info-bg); color: var(--text); }
    .host-btn.danger { border-color: var(--danger); color: var(--danger); }
    .host-btn.danger:hover { background: var(--danger-bg); }
    .host-btn.primary { border-color: var(--primary); color: var(--primary); }
    .host-btn.primary:hover { background: var(--info-bg); }
    .bulk-actions { margin-top: 8px; text-align: right; }
    .bulk-btn { display: inline-block; background: none; border: 1px solid var(--border); color: var(--text-secondary); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.75rem; font-weight: 600; }
    .bulk-btn:hover { background: var(--info-bg); color: var(--text); }
    .bulk-btn.success { border-color: var(--success); color: var(--success); }
    .admin-required { font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning-border); white-space: nowrap; }
    .bulk-btn.success:hover { background: var(--success-bg); }
    .bulk-btn.danger { border-color: var(--danger-border); color: var(--danger); }
    .bulk-btn.danger:hover { background: var(--danger-bg); }
    .history-entry { padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 0.813rem; color: var(--text-secondary); text-align: left; display: flex; gap: 8px; }
    .history-action { font-weight: 600; }
    .history-action.approved { color: var(--success); }
    .history-action.revoked { color: var(--danger); }
    .history-action.auto_approved { color: var(--primary); }
    .history-action.rejected { color: var(--danger); }
    .history-action.elevated { color: var(--primary); }
    .history-action.extended { color: var(--primary); }
    .history-action.rotated_breakglass { color: var(--text-secondary); }
    .history-actor { font-size: 0.7rem; color: var(--text-secondary); font-weight: 400; }
    .history-time { flex-shrink: 0; }
    .empty-state { color: var(--text-secondary); margin: 16px 0; font-size: 0.875rem; }
    .view-all { display: block; text-align: left; margin-top: 8px; font-size: 0.813rem; color: var(--primary); text-decoration: none; font-weight: 600; }
    .view-all:hover { text-decoration: underline; }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    // Select the detected TZ in all tz-select dropdowns
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
  });
  var es = new EventSource('/api/events');
  es.addEventListener('update', function(e) {
    location.reload();
  });
  es.onerror = function() {
    // Reconnect happens automatically via EventSource
    // Fallback: reload after 60s if disconnected
    setTimeout(function() { if (es.readyState === 2) location.reload(); }, 60000);
  };
  </script>
</head>
<body class="wide">
  <div class="card">
    <h2>{{call .T "app_name"}}</h2>

    <nav class="nav">
      <a href="/" class="{{if eq .ActivePage "sessions"}}active{{end}}">{{call .T "sessions"}}</a>
      <a href="/history">{{call .T "history"}}</a>
      <a href="/hosts">{{call .T "hosts"}}</a>
      <a href="/info">{{call .T "info"}}</a>
      <div class="profile-menu" tabindex="-1">
        <button class="profile-btn" type="button" aria-label="User menu">{{if .Avatar}}<img src="{{.Avatar}}" class="profile-img" alt="">{{else}}{{.Initial}}{{end}}</button>
        <div class="profile-dropdown">
          <div class="profile-dropdown-label">{{.Username}}{{if .IsAdmin}} <span style="font-size:0.75em;color:var(--primary);font-weight:700">({{call .T "admin"}})</span>{{end}}</div>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/">
            <select name="lang" class="lang-select" aria-label="Language">
              {{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/">
            <select name="tz" class="tz-select" aria-label="Timezone">` + tzOptionsHTML + `
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-options">
            <a href="/theme?set=system&from=/" class="theme-option{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/" class="theme-option{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/" class="theme-option{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="profile-dropdown-divider"></div>
          <a href="/signout" class="profile-dropdown-item" style="color:var(--danger)">{{call .T "sign_out"}}</a>
        </div>
      </div>
    </nav>

    {{range .Flashes}}<div class="banner banner-success" role="alert">{{.}}</div>{{end}}

    {{if .Pending}}
    <div class="section-label pending">{{call .T "pending_requests"}}</div>
    <div class="list" role="list" aria-label="{{call .T "pending_requests"}}">
      {{range .Pending}}
      <div class="row" role="listitem">
        <div class="row-info">
          <span class="row-host">{{.Hostname}}</span>
          {{if $.IsAdmin}}<span class="row-sub" style="color:var(--primary)">{{.Username}}</span>{{end}}
          {{if .AdminRequired}}<span class="admin-required">&#x1F512; {{call $.T "admin_approval_required"}}</span>{{end}}
          <span class="row-code">{{.Code}}</span>
          <span class="row-sub">{{call $.T "expires_in"}} {{.ExpiresIn}}</span>
        </div>
        <div style="display: flex; gap: 8px; flex-shrink: 0;">
          {{if not .AdminRequired}}
          <form method="POST" action="/api/challenges/approve">
            <input type="hidden" name="challenge_id" value="{{.ID}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="approve-btn" aria-label="{{call $.T "approve"}} {{.Hostname}}">{{call $.T "approve"}}</button>
          </form>
          {{else if $.IsAdmin}}
          <form method="POST" action="/api/challenges/approve">
            <input type="hidden" name="challenge_id" value="{{.ID}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="approve-btn" aria-label="{{call $.T "approve"}} {{.Hostname}}">{{call $.T "approve"}}</button>
          </form>
          {{end}}
          <form method="POST" action="/api/challenges/reject">
            <input type="hidden" name="challenge_id" value="{{.ID}}">
            <input type="hidden" name="username" value="{{$.Username}}">
            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
            <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
            <button type="submit" class="host-btn danger" aria-label="{{call $.T "reject"}} {{.Hostname}}">{{call $.T "reject"}}</button>
          </form>
        </div>
      </div>
      {{end}}
    </div>
    <div style="display: flex; gap: 8px; justify-content: flex-end; margin-top: 8px;">
      <form method="POST" action="/api/challenges/approve-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn success" onclick="return confirm('Approve all pending requests?')">{{call .T "approve_all"}}</button>
      </form>
      <form method="POST" action="/api/challenges/reject-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn danger" onclick="return confirm('Reject all pending requests?')">{{call .T "reject_all"}}</button>
      </form>
    </div>
    {{end}}

    {{if .Sessions}}
    <div class="section-label">{{call .T "active_sessions"}}</div>
    <div class="list" role="list" aria-label="{{call .T "active_sessions"}}">
      {{range .Sessions}}
      <div class="row" role="listitem">
        <div class="row-info">
          <span class="row-host">{{.Hostname}}</span>
          {{if $.IsAdmin}}<span class="row-sub" style="color:var(--primary)">{{.Username}}</span>{{end}}
          <span class="row-sub">{{.Remaining}} {{call $.T "remaining"}}</span>
        </div>
        <form method="POST" action="/api/sessions/extend" style="display:inline">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <button type="submit" class="host-btn primary" onclick="return confirm('Extend session on {{.Hostname}} to maximum?')">{{call $.T "extend"}}</button>
        </form>
        <form method="POST" action="/api/sessions/revoke">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          {{if $.IsAdmin}}<input type="hidden" name="session_username" value="{{.Username}}">{{end}}
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <button type="submit" class="host-btn danger" aria-label="{{call $.T "revoke"}} {{.Hostname}}" onclick="return confirm('Revoke session on {{.Hostname}}?')">{{call $.T "revoke"}}</button>
        </form>
      </div>
      {{end}}
    </div>
    <div class="bulk-actions">
      <form method="POST" action="/api/sessions/extend-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn primary" onclick="return confirm('Extend all active sessions to maximum?')">{{call .T "extend_all"}}</button>
      </form>
      <form method="POST" action="/api/sessions/revoke-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn danger" onclick="return confirm('Revoke all active sessions?')">{{call .T "revoke_all"}}</button>
      </form>
    </div>
    {{end}}

    {{if not .Pending}}{{if not .Sessions}}
    <p class="empty-state">{{call .T "no_pending_or_active"}}</p>
    {{end}}{{end}}

    {{if .History}}
    <div class="section-label">{{call .T "recent_activity"}}</div>
    <div class="list">
      {{range .History}}
      <div class="history-entry">
        <span class="history-action {{.Action}}">{{if eq .Action "auto_approved"}}{{call $.T "auto_approved"}}{{else if eq .Action "approved"}}{{call $.T "approved"}}{{else if eq .Action "revoked"}}{{call $.T "revoked"}}{{else if eq .Action "rejected"}}{{call $.T "rejected"}}{{else if eq .Action "elevated"}}{{call $.T "elevated"}}{{else if eq .Action "extended"}}{{call $.T "extended"}}{{else if eq .Action "rotated_breakglass"}}{{call $.T "rotated_breakglass"}}{{else}}{{.Action}}{{end}}</span>{{if .Actor}}<span class="history-actor">by {{.Actor}}</span>{{end}}
        <span>{{.Hostname}}</span>
        {{if .Code}}<span class="row-code">{{.Code}}</span>{{end}}
        <span class="history-time">{{timeAgo .Timestamp}}</span>
      </div>
      {{end}}
    </div>
    {{if .HasMoreHistory}}<a href="/history" class="view-all">{{call .T "view_all_activity"}} &rarr;</a>{{end}}
    {{end}}
  </div>
</body>
</html>`

const historyPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>History - pam-pocketid</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="240">
  <style>` + sharedCSS + navCSS + `
    body { align-items: flex-start; padding-top: 32px; }
    .history-action { font-weight: 600; }
    .history-action.approved { color: var(--success); }
    .history-action.revoked { color: var(--danger); }
    .history-action.auto_approved { color: var(--primary); }
    .history-action.rejected { color: var(--danger); }
    .history-action.elevated { color: var(--primary); }
    .history-action.extended { color: var(--primary); }
    .history-action.rotated_breakglass { color: var(--text-secondary); }
    .history-actor { font-size: 0.7rem; color: var(--text-secondary); font-weight: 400; }
    .empty-state { color: var(--text-secondary); margin: 16px 0; font-size: 0.875rem; }
    .search-bar { margin-bottom: 16px; text-align: left; }
    .search-bar input[type="text"] {
      width: 100%;
      padding: 10px 14px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 0.875rem;
      background: var(--card-bg);
      color: var(--text);
      outline: none;
    }
    .search-bar input[type="text"]:focus { border-color: var(--primary); box-shadow: var(--focus-ring); }
    .export-links { display: inline-flex; gap: 4px; margin-left: 8px; }
    .export-btn { font-size: 0.75rem; padding: 4px 8px; border: 1px solid var(--border); border-radius: 4px; color: var(--text-secondary); text-decoration: none; }
    .export-btn:hover { background: var(--info-bg); color: var(--text); }
    .pagination { display: flex; justify-content: center; align-items: center; gap: 16px; margin-top: 16px; font-size: 0.875rem; flex-wrap: wrap; }
    .pagination a { color: var(--primary); text-decoration: none; font-weight: 600; }
    .pagination a:hover { text-decoration: underline; }
    .page-info { color: var(--text-secondary); }
    .page-size-form { display: inline-flex; align-items: center; gap: 4px; }
    .page-size-form select { padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.813rem; background: var(--card-bg); color: var(--text); }
    .page-size-btn { padding: 4px 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.813rem; background: var(--card-bg); color: var(--text); cursor: pointer; }
    .page-size-btn:hover { background: var(--info-bg); }
    .history-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; }
    .history-table th { padding: 8px 12px; border-bottom: 2px solid var(--border); font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); white-space: nowrap; }
    .history-table th a { color: var(--text-secondary); text-decoration: none; font-size: 0.75rem; text-transform: none; }
    .history-table th a:hover { color: var(--text); }
    .sort-arrow { font-size: 0.875rem; }
    .filter-clear { font-size: 0.75rem; color: var(--danger); text-decoration: none; margin-left: 4px; }
    .filter-clear:hover { text-decoration: underline; }
    .filter-label { font-size: 0.688rem; font-weight: 400; text-transform: none; letter-spacing: 0; }
    .history-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    .col-time { white-space: nowrap; }
    .timestamp { display: block; }
    .time-ago { display: block; font-size: 0.75rem; color: var(--text-secondary); }
    .col-host { overflow: hidden; text-overflow: ellipsis; max-width: 200px; }
    .col-code { font-family: monospace; font-size: 0.813rem; color: var(--text-secondary); white-space: nowrap; }
    .col-filter-form { display: inline-flex; align-items: center; gap: 2px; margin: 0; padding: 0; text-transform: none; }
    .sort-btn { display: inline-block; padding: 4px 6px; margin-left: 4px; color: var(--border); text-decoration: none; font-size: 0.75rem; text-transform: none; border-radius: 4px; }
    .sort-btn:hover { color: var(--text); background: var(--info-bg); }
    .sort-btn.active { color: var(--primary); }
    .col-filter-select {
      padding: 4px 8px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 400;
      text-transform: none;
      background: var(--card-bg);
      color: var(--text);
      cursor: pointer;
      appearance: none;
      -webkit-appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath d='M3 5l3 3 3-3' fill='none' stroke='%236b7280' stroke-width='1.5'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 6px center;
      padding-right: 22px;
    }
    .col-filter-select:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(59,130,246,0.2);
    }
    .filter-toolbar { display: none; }
    .timeline { margin: 16px 0 8px; }
    .timeline-bars { display: flex; align-items: flex-end; gap: 2px; height: 44px; }
    .timeline-bar { flex: 1; background: var(--primary); border-radius: 2px 2px 0 0; min-height: 2px; opacity: 0.5; transition: opacity 0.15s, transform 0.15s; cursor: pointer; text-decoration: none; display: block; }
    .timeline-bar:hover { opacity: 1; transform: scaleY(1.1); transform-origin: bottom; }
    .timeline-bar.now { background: var(--success); opacity: 0.8; }
    .timeline-bar.timeline-active { opacity: 1; outline: 2px solid var(--primary); outline-offset: 1px; }
    .timeline-bar.timeline-active.now { outline-color: var(--success); }
    .timeline-label { font-size: 0.7rem; color: var(--text-secondary); margin-top: 4px; text-align: right; }
    .time-filter-banner { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 6px; background: var(--info-bg); border: 1px solid var(--border); margin-bottom: 12px; font-size: 0.813rem; color: var(--text-secondary); }
    .time-filter-clear { color: var(--danger); text-decoration: none; font-weight: 600; margin-left: auto; font-size: 0.75rem; }
    .time-filter-clear:hover { text-decoration: underline; }
    @media (max-width: 600px) {
      .history-table, .history-table thead, .history-table tbody, .history-table th, .history-table td, .history-table tr {
        display: block;
      }
      .history-table thead { display: none; }
      .history-table tr { padding: 12px 0; border-bottom: 1px solid var(--border); }
      .history-table td { padding: 2px 0; border: none; }
      .history-table td:before { content: attr(data-label); font-weight: 600; font-size: 0.75rem; color: var(--text-secondary); display: block; }
      .filter-toolbar { display: flex; gap: 8px; margin-bottom: 12px; }
      .filter-toolbar .col-filter-select { flex: 1; }
    }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    // Select the detected TZ in all tz-select dropdowns
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
    // Live search: filter table rows as user types
    var searchInput=document.querySelector('.search-bar input[name="q"]');
    if(searchInput){
      searchInput.addEventListener('input',function(){
        var q=this.value.toLowerCase();
        document.querySelectorAll('.history-table tbody tr').forEach(function(row){
          var text=row.textContent.toLowerCase();
          row.style.display=text.indexOf(q)!==-1?'':'none';
        });
      });
    }
  });
  </script>
</head>
<body class="wide">
  <div class="card">
    <h2>{{call .T "app_name"}}</h2>

    <nav class="nav">
      <a href="/">{{call .T "sessions"}}</a>
      <a href="/history" class="{{if eq .ActivePage "history"}}active{{end}}">{{call .T "history"}}</a>
      <a href="/hosts">{{call .T "hosts"}}</a>
      <a href="/info">{{call .T "info"}}</a>
      <div class="profile-menu" tabindex="-1">
        <button class="profile-btn" type="button" aria-label="User menu">{{if .Avatar}}<img src="{{.Avatar}}" class="profile-img" alt="">{{else}}{{.Initial}}{{end}}</button>
        <div class="profile-dropdown">
          <div class="profile-dropdown-label">{{.Username}}</div>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/history">
            <select name="lang" class="lang-select" aria-label="Language">
              {{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/history">
            <select name="tz" class="tz-select" aria-label="Timezone">` + tzOptionsHTML + `
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-options">
            <a href="/theme?set=system&from=/history" class="theme-option{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/history" class="theme-option{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/history" class="theme-option{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="profile-dropdown-divider"></div>
          <a href="/signout" class="profile-dropdown-item" style="color:var(--danger)">{{call .T "sign_out"}}</a>
        </div>
      </div>
    </nav>


    {{if .Timeline}}
    <div class="timeline">
      <div class="timeline-bars">
        {{range .Timeline}}<a href="/history?hours_ago={{.HoursAgo}}&per_page={{$.PerPage}}" class="timeline-bar{{if .IsNow}} now{{end}}{{if eqInt .HoursAgo $.ActiveHoursAgo}} timeline-active{{end}}" style="height:{{.Height}}px" title="{{.Details}}"></a>{{end}}
      </div>
      <div class="timeline-label">24h</div>
    </div>
    {{end}}

    {{if .HoursAgo}}
    <div class="time-filter-banner">
      <span>{{call .T "filtered_to_one_hour"}}</span>
      <a href="/history?q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}" class="time-filter-clear">{{call .T "clear_time_filter"}}</a>
    </div>
    {{end}}

    <form method="GET" action="/history" class="search-bar">
      <input type="hidden" name="action" value="{{.ActionFilter}}">
      <input type="hidden" name="hostname" value="{{.HostFilter}}">
      <input type="hidden" name="sort" value="{{.Sort}}">
      <input type="hidden" name="order" value="{{.Order}}">
      <input type="hidden" name="per_page" value="{{.PerPage}}">
      {{if .HoursAgo}}<input type="hidden" name="hours_ago" value="{{.HoursAgo}}">{{end}}
      <input type="text" name="q" value="{{.Query}}" placeholder="{{call .T "search"}}" aria-label="Search">
    </form>
    <div class="export-links">
      <a href="/api/history/export?format=csv" class="export-btn">{{call .T "export_csv"}}</a>
      <a href="/api/history/export?format=json" class="export-btn">{{call .T "export_json"}}</a>
    </div>

    <div class="filter-toolbar">
      <form method="GET" action="/history" class="filter-form">
        <input type="hidden" name="q" value="{{.Query}}">
        <input type="hidden" name="sort" value="{{.Sort}}">
        <input type="hidden" name="order" value="{{.Order}}">
        <input type="hidden" name="per_page" value="{{.PerPage}}">
        <select name="action" class="col-filter-select" aria-label="Filter by action">
          <option value="">{{call .T "action_all"}}</option>
          {{range .ActionOptions}}<option value="{{.Value}}" {{if eq .Value $.ActionFilter}}selected{{end}}>{{.Label}}</option>{{end}}
        </select>
        <select name="hostname" class="col-filter-select" aria-label="Filter by hostname">
          <option value="">{{call .T "host_all"}}</option>
          {{range .HostOptions}}<option value="{{.}}" {{if eq . $.HostFilter}}selected{{end}}>{{.}}</option>{{end}}
        </select>
      </form>
    </div>

    {{if .History}}
    <table class="history-table">
      <thead>
        <tr>
          <th>{{call .T "time"}} <a href="/history?sort=timestamp&order={{if eq .Sort "timestamp"}}{{if eq .Order "desc"}}asc{{else}}desc{{end}}{{else}}desc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "timestamp"}} active{{end}}" title="{{call .T "sort_by_time"}}">{{if and (eq .Sort "timestamp") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th><form method="GET" action="/history" class="col-filter-form">
  <input type="hidden" name="hostname" value="{{.HostFilter}}">
  <input type="hidden" name="q" value="{{.Query}}">
  <input type="hidden" name="sort" value="{{.Sort}}">
  <input type="hidden" name="order" value="{{.Order}}">
  <input type="hidden" name="per_page" value="{{.PerPage}}">
  <select name="action" class="col-filter-select" aria-label="Filter by action">
    <option value="">{{call .T "action_all"}}</option>
    {{range .ActionOptions}}<option value="{{.Value}}" {{if eq .Value $.ActionFilter}}selected{{end}}>{{.Label}}</option>{{end}}
  </select>
</form><a href="/history?sort=action&order={{if eq .Sort "action"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "action"}} active{{end}}" title="{{call .T "sort_by_action"}}">{{if and (eq .Sort "action") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th><form method="GET" action="/history" class="col-filter-form">
  <input type="hidden" name="action" value="{{.ActionFilter}}">
  <input type="hidden" name="q" value="{{.Query}}">
  <input type="hidden" name="sort" value="{{.Sort}}">
  <input type="hidden" name="order" value="{{.Order}}">
  <input type="hidden" name="per_page" value="{{.PerPage}}">
  <select name="hostname" class="col-filter-select" aria-label="Filter by hostname">
    <option value="">{{call .T "host_all"}}</option>
    {{range .HostOptions}}<option value="{{.}}" {{if eq . $.HostFilter}}selected{{end}}>{{.}}</option>{{end}}
  </select>
</form><a href="/history?sort=hostname&order={{if eq .Sort "hostname"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "hostname"}} active{{end}}" title="{{call .T "sort_by_host"}}">{{if and (eq .Sort "hostname") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
          <th>{{call .T "code"}} <a href="/history?sort=code&order={{if eq .Sort "code"}}{{if eq .Order "asc"}}desc{{else}}asc{{end}}{{else}}asc{{end}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&per_page={{.PerPage}}" class="sort-btn{{if eq .Sort "code"}} active{{end}}" title="{{call .T "sort_by_code"}}">{{if and (eq .Sort "code") (eq .Order "asc")}}&#x25b2;{{else}}&#x25bc;{{end}}</a></th>
        </tr>
      </thead>
      <tbody>
        {{range .History}}
        <tr>
          <td data-label="{{call $.T "time"}}" class="col-time">
            <span class="timestamp">{{.FormattedTime}}</span>
            <span class="time-ago">({{.TimeAgo}})</span>
          </td>
          <td data-label="{{call $.T "action"}}"><span class="history-action {{.Action}}">{{.ActionLabel}}</span>{{if .Actor}} <span class="history-actor">by {{.Actor}}</span>{{end}}</td>
          <td data-label="{{call $.T "host"}}" class="col-host">{{.Hostname}}</td>
          <td data-label="{{call $.T "code"}}" class="col-code">{{if .Code}}{{.Code}}{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    <div class="pagination">
      {{if .HasPrev}}<a href="/history?page={{sub .Page 1}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}">&#8592; {{call .T "previous"}}</a>{{end}}
      <span class="page-info">{{call .T "page"}} {{.Page}} {{call .T "of"}} {{.TotalPages}}</span>
      {{if .HasNext}}<a href="/history?page={{add .Page 1}}&q={{.Query}}&action={{.ActionFilter}}&hostname={{.HostFilter}}&sort={{.Sort}}&order={{.Order}}&per_page={{.PerPage}}">{{call .T "next"}} &#8594;</a>{{end}}
      <form method="GET" action="/history" class="page-size-form">
        <input type="hidden" name="action" value="{{.ActionFilter}}">
        <input type="hidden" name="hostname" value="{{.HostFilter}}">
        <input type="hidden" name="sort" value="{{.Sort}}">
        <input type="hidden" name="order" value="{{.Order}}">
        <input type="hidden" name="q" value="{{.Query}}">
        <select name="per_page" class="page-size-select" aria-label="Page size">
          {{range .PerPageOptions}}<option value="{{.}}" {{if eqInt . $.PerPage}}selected{{end}}>{{.}}</option>{{end}}
        </select>
        <button type="submit" class="page-size-btn">{{call .T "go"}}</button>
      </form>
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_activity"}}</p>
    {{end}}
  </div>
</body>
</html>`

const hostsPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>Hosts - pam-pocketid</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>` + sharedCSS + navCSS + `
    body { align-items: flex-start; padding-top: 32px; }
    .section-label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      margin: 24px 0 8px;
      text-align: left;
    }
    .list { text-align: left; margin: 0 0 8px; }
    .row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); gap: 12px; }
    .row-info { min-width: 0; flex: 1; }
    .row-host { font-weight: 600; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-sub { color: var(--text-secondary); font-size: 0.813rem; display: block; }
    .row-active { color: var(--success); font-size: 0.813rem; font-weight: 600; display: block; }
    .banner { padding: 10px 16px; border-radius: 8px; margin-bottom: 12px; font-size: 0.875rem; font-weight: 600; text-align: left; }
    .banner-success { background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }
    .host-btn { display: inline-block; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; font-weight: 600; white-space: nowrap; border: 1px solid var(--border); background: none; color: var(--text-secondary); text-decoration: none; text-align: center; line-height: 1.4; }
    .host-btn:hover { background: var(--info-bg); color: var(--text); }
    .host-btn.danger { border-color: var(--danger); color: var(--danger); }
    .host-btn.danger:hover { background: var(--danger-bg); }
    .host-btn.primary { border-color: var(--primary); color: var(--primary); }
    .host-btn.primary:hover { background: var(--info-bg); }
    .host-btn.filled { background: var(--primary); border-color: var(--primary); color: #fff; }
    .host-btn.filled:hover { background: var(--primary-hover); }
    .elevate-form { display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
    .elevate-form select {
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-size: 0.813rem;
      background: var(--card-bg);
      color: var(--text);
      cursor: pointer;
    }
    .empty-state { color: var(--text-secondary); margin: 16px 0; font-size: 0.875rem; }
    .bulk-actions { margin: 16px 0 8px; text-align: right; }
    .bulk-btn { background: none; border: 1px solid var(--border); color: var(--text-secondary); padding: 6px 16px; border-radius: 8px; cursor: pointer; font-size: 0.813rem; font-weight: 600; }
    .bulk-btn:hover { background: var(--info-bg); color: var(--text); }
    .bulk-btn.primary { border-color: var(--primary); color: var(--primary); }
    .bulk-btn.primary:hover { background: var(--info-bg); }
    .bulk-btn.danger { border-color: var(--danger-border); color: var(--danger); }
    .bulk-btn.danger:hover { background: var(--danger-bg); }
    .host-group { font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; background: var(--info-bg); color: var(--text-secondary); margin-left: 8px; vertical-align: middle; }
    .group-filter { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 0.813rem; }
    .group-filter select { padding: 6px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--card-bg); color: var(--text); font-size: 0.813rem; cursor: pointer; }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    // Select the detected TZ in all tz-select dropdowns
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
  });
  var es = new EventSource('/api/events');
  es.addEventListener('update', function(e) {
    location.reload();
  });
  es.onerror = function() {
    // Reconnect happens automatically via EventSource
    // Fallback: reload after 60s if disconnected
    setTimeout(function() { if (es.readyState === 2) location.reload(); }, 60000);
  };
  </script>
</head>
<body class="wide">
  <div class="card">
    <h2>{{call .T "app_name"}}</h2>

    <nav class="nav">
      <a href="/">{{call .T "sessions"}}</a>
      <a href="/history">{{call .T "history"}}</a>
      <a href="/hosts" class="{{if eq .ActivePage "hosts"}}active{{end}}">{{call .T "hosts"}}</a>
      <a href="/info">{{call .T "info"}}</a>
      <div class="profile-menu" tabindex="-1">
        <button class="profile-btn" type="button" aria-label="User menu">{{if .Avatar}}<img src="{{.Avatar}}" class="profile-img" alt="">{{else}}{{.Initial}}{{end}}</button>
        <div class="profile-dropdown">
          <div class="profile-dropdown-label">{{.Username}}</div>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/hosts">
            <select name="lang" class="lang-select" aria-label="Language">
              {{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/hosts">
            <select name="tz" class="tz-select" aria-label="Timezone">` + tzOptionsHTML + `
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-options">
            <a href="/theme?set=system&from=/hosts" class="theme-option{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/hosts" class="theme-option{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/hosts" class="theme-option{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="profile-dropdown-divider"></div>
          <a href="/signout" class="profile-dropdown-item" style="color:var(--danger)">{{call .T "sign_out"}}</a>
        </div>
      </div>
    </nav>

    {{range .Flashes}}<div class="banner banner-success" role="alert">{{.}}</div>{{end}}

    {{if .AllGroups}}
    <div class="group-filter">
      <form method="GET" action="/hosts">
        <select name="group" class="col-filter-select" aria-label="Filter by group">
          <option value="">All groups</option>
          {{range .AllGroups}}<option value="{{.}}" {{if eq . $.GroupFilter}}selected{{end}}>{{.}}</option>{{end}}
        </select>
      </form>
      {{if .GroupFilter}}<a href="/hosts" style="font-size:0.813rem;color:var(--text-secondary)">clear filter</a>{{end}}
    </div>
    {{end}}

    {{if .Hosts}}
    <div class="list" role="list" aria-label="{{call .T "known_hosts"}}">
      {{range .Hosts}}
      <div class="row" role="listitem">
        <div class="row-info">
          <span class="row-host">{{.Hostname}}{{if .Group}}<span class="host-group">{{.Group}}</span>{{end}}</span>
          {{if .Active}}
            <span class="row-active">{{call $.T "active"}} — {{.Remaining}} {{call $.T "remaining"}}</span>
          {{else}}
            <span class="row-sub">{{call $.T "no_active_session"}}</span>
          {{end}}
          {{if .Escrowed}}
            <span class="row-sub">{{if .EscrowExpired}}{{call $.T "breakglass_expired"}} ({{call $.T "escrowed"}} {{.EscrowAge}} {{call $.T "ago"}}){{else}}{{call $.T "breakglass_escrowed"}} ({{.EscrowAge}} {{call $.T "ago"}}){{end}}</span>
          {{end}}
        </div>
        {{if .Escrowed}}
        {{if .EscrowLink}}
        <a href="{{.EscrowLink}}" target="_blank" class="host-btn">{{$.EscrowLinkLabel}}</a>
        {{end}}
        <form method="POST" action="/api/hosts/rotate" style="display:inline">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <button type="submit" class="host-btn" onclick="return confirm('Request breakglass rotation on {{.Hostname}}?')">{{call $.T "rotate"}}</button>
        </form>
        {{end}}
        {{if .Active}}
        <form method="POST" action="/api/sessions/extend" style="display:inline">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <input type="hidden" name="from" value="/hosts">
          <button type="submit" class="host-btn primary">{{call $.T "extend"}}</button>
        </form>
        <form method="POST" action="/api/sessions/revoke">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          <input type="hidden" name="from" value="/hosts">
          <button type="submit" class="host-btn danger" onclick="return confirm('Revoke session on {{.Hostname}}?')">{{call $.T "revoke"}}</button>
        </form>
        {{else}}
        <form method="POST" action="/api/hosts/elevate" class="elevate-form">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <input type="hidden" name="username" value="{{$.Username}}">
          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
          <input type="hidden" name="csrf_ts" value="{{$.CSRFTs}}">
          {{if $.Durations}}
          <select name="duration" aria-label="Duration">
            {{range $.Durations}}<option value="{{.Value}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}
          </select>
          {{end}}
          <button type="submit" class="host-btn filled">{{call $.T "elevate"}}</button>
        </form>
        {{end}}
      </div>
      {{end}}
    </div>
    <div class="bulk-actions">
      <form method="POST" action="/api/sessions/extend-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <input type="hidden" name="from" value="/hosts">
        <button type="submit" class="bulk-btn primary" onclick="return confirm('Extend all active sessions to maximum?')">{{call .T "extend_all"}}</button>
      </form>
      <form method="POST" action="/api/sessions/revoke-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <input type="hidden" name="from" value="/hosts">
        <button type="submit" class="bulk-btn danger" onclick="return confirm('Revoke all active sessions?')">{{call .T "revoke_all"}}</button>
      </form>
      {{if .HasEscrowedHosts}}
      <form method="POST" action="/api/hosts/rotate-all" style="display:inline">
        <input type="hidden" name="username" value="{{.Username}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="csrf_ts" value="{{.CSRFTs}}">
        <button type="submit" class="bulk-btn" onclick="return confirm('Request breakglass rotation on all hosts?')">{{call .T "rotate_all"}}</button>
      </form>
      {{end}}
    </div>
    {{else}}
    <p class="empty-state">{{call .T "no_known_hosts"}} {{call .T "hosts_appear_after_approve"}}</p>
    {{end}}
  </div>
</body>
</html>`

const infoPageHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}" class="{{if eq .Theme "dark"}}theme-dark{{else if eq .Theme "light"}}theme-light{{end}}">
<head>
  <title>Info - pam-pocketid</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="240">
  <style>` + sharedCSS + navCSS + `
    body { align-items: flex-start; padding-top: 32px; }
    .info-section { margin-bottom: 24px; }
    .info-section h3 { font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); margin-bottom: 12px; }
    .info-table { width: 100%; border-collapse: collapse; }
    .info-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 0.875rem; }
    .info-label { color: var(--text-secondary); width: 40%; }
    .info-value-yes { color: var(--success); }
    .info-value-no { color: var(--text-secondary); }
  </style>
  <script nonce="{{.CSPNonce}}">
  if(!document.cookie.split(';').some(function(c){return c.trim().indexOf('pam_tz=')===0;})){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    if(tz){var d=new Date();d.setTime(d.getTime()+86400000);document.cookie='pam_tz='+tz+';path=/;expires='+d.toUTCString()+';SameSite=Lax';}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.querySelectorAll('.col-filter-select,.page-size-select,.tz-select,.lang-select').forEach(function(el){el.addEventListener('change',function(){this.form.submit();});});
    // Select the detected TZ in all tz-select dropdowns
    document.querySelectorAll('.tz-select').forEach(function(sel){
      for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===tz){sel.selectedIndex=i;break;}}
    });
  });
  </script>
</head>
<body class="wide">
  <div class="card">
    <h2>{{call .T "app_name"}}</h2>

    <nav class="nav">
      <a href="/">{{call .T "sessions"}}</a>
      <a href="/history">{{call .T "history"}}</a>
      <a href="/hosts">{{call .T "hosts"}}</a>
      <a href="/info" class="{{if eq .ActivePage "info"}}active{{end}}">{{call .T "info"}}</a>
      <div class="profile-menu" tabindex="-1">
        <button class="profile-btn" type="button" aria-label="User menu">{{if .Avatar}}<img src="{{.Avatar}}" class="profile-img" alt="">{{else}}{{.Initial}}{{end}}</button>
        <div class="profile-dropdown">
          <div class="profile-dropdown-label">{{.Username}}</div>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "language"}}</div>
          <form method="GET" action="/info">
            <select name="lang" class="lang-select" aria-label="Language">
              {{range .Languages}}<option value="{{.Code}}" {{if eq .Code $.Lang}}selected{{end}}>{{.Name}}</option>{{end}}
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "timezone"}}</div>
          <form method="GET" action="/info">
            <select name="tz" class="tz-select" aria-label="Timezone">` + tzOptionsHTML + `
            </select>
          </form>
          <div class="profile-dropdown-divider"></div>
          <div class="profile-dropdown-label">{{call .T "theme"}}</div>
          <div class="theme-options">
            <a href="/theme?set=system&from=/info" class="theme-option{{if eq .Theme ""}} active{{end}}">{{call .T "theme_system"}}</a>
            <a href="/theme?set=dark&from=/info" class="theme-option{{if eq .Theme "dark"}} active{{end}}">{{call .T "theme_dark"}}</a>
            <a href="/theme?set=light&from=/info" class="theme-option{{if eq .Theme "light"}} active{{end}}">{{call .T "theme_light"}}</a>
          </div>
          <div class="profile-dropdown-divider"></div>
          <a href="/signout" class="profile-dropdown-item" style="color:var(--danger)">{{call .T "sign_out"}}</a>
        </div>
      </div>
    </nav>

    <div class="info-section">
      <h3>{{call .T "server_config"}}</h3>
      <table class="info-table">
        <tr><td class="info-label">{{call .T "version"}}</td><td>{{.Version}}</td></tr>
        <tr><td class="info-label">{{call .T "grace_period"}}</td><td>{{.GracePeriod}}</td></tr>
        <tr><td class="info-label">{{call .T "onetap_max_age"}}</td><td>{{.OneTapMaxAge}}</td></tr>
        <tr><td class="info-label">{{call .T "challenge_ttl"}}</td><td>{{.ChallengeTTL}}</td></tr>
        <tr><td class="info-label">{{call .T "breakglass_type"}}</td><td>{{.BreakglassType}}</td></tr>
        <tr><td class="info-label">{{call .T "breakglass_rotation_days"}}</td><td>{{.BreakglassRotation}}</td></tr>
        <tr><td class="info-label">{{call .T "token_cache"}}</td><td>{{.TokenCache}}</td></tr>
        <tr><td class="info-label">{{call .T "default_page_size"}}</td><td>{{.DefaultPageSize}}</td></tr>
        <tr><td class="info-label">{{call .T "escrow_configured"}}</td><td>{{.EscrowConfigured}}</td></tr>
        <tr><td class="info-label">{{call .T "notifications_configured"}}</td><td>{{.NotifyConfigured}}</td></tr>
        <tr><td class="info-label">{{call .T "host_registry"}}</td><td>{{.HostRegistry}}</td></tr>
        <tr><td class="info-label">{{call .T "session_persistence"}}</td><td>{{.SessionPersistence}}</td></tr>
        <tr><td class="info-label">{{call .T "admin_groups"}}</td><td>{{.AdminGroups}}</td></tr>
        <tr><td class="info-label">{{call .T "admin_approval_hosts"}}</td><td>{{.AdminApprovalHosts}}</td></tr>
      </table>
    </div>

    <div class="info-section">
      <h3>{{call .T "system_info"}}</h3>
      <table class="info-table">
        <tr><td class="info-label">{{call .T "uptime"}}</td><td>{{.Uptime}}</td></tr>
        <tr><td class="info-label">{{call .T "go_version"}}</td><td>{{.GoVersion}}</td></tr>
        <tr><td class="info-label">{{call .T "os_arch"}}</td><td>{{.OSArch}}</td></tr>
        <tr><td class="info-label">{{call .T "goroutines"}}</td><td>{{.Goroutines}}</td></tr>
        <tr><td class="info-label">{{call .T "memory_usage"}}</td><td>{{.MemUsage}}</td></tr>
        <tr><td class="info-label">{{call .T "active_sessions"}}</td><td>{{.ActiveSessionsCount}}</td></tr>
      </table>
    </div>
  </div>
</body>
</html>`

const approvalDeniedHTML = `<!DOCTYPE html>
<html lang="{{.Lang}}"{{if eq .Theme "dark"}} class="theme-dark"{{else if eq .Theme "light"}} class="theme-light"{{end}}>
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
<html lang="{{.Lang}}"{{if eq .Theme "dark"}} class="theme-dark"{{else if eq .Theme "light"}} class="theme-light"{{end}}>
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
<html lang="{{.Lang}}"{{if eq .Theme "dark"}} class="theme-dark"{{else if eq .Theme "light"}} class="theme-light"{{end}}>
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
<html lang="{{.Lang}}"{{if eq .Theme "dark"}} class="theme-dark"{{else if eq .Theme "light"}} class="theme-light"{{end}}>
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

