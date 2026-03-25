package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
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
	pocketIDClient *PocketIDClient
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
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
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

	s.pocketIDClient = NewPocketIDClient(cfg.PocketIDAPIURL, cfg.PocketIDAPIKey)

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
	s.mux.HandleFunc("/admin", s.handleAdmin)
	s.mux.HandleFunc("/admin/info", s.handleAdminInfo)
	s.mux.HandleFunc("/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/admin/groups", s.handleAdminGroups)
	s.mux.HandleFunc("/admin/hosts", s.handleAdminHosts)
s.mux.HandleFunc("/api/users/remove", s.handleRemoveUser)
	// Redirect old URLs for bookmarks
	s.mux.HandleFunc("/hosts", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/hosts", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/info", http.StatusMovedPermanently)
	})
	s.mux.HandleFunc("/api/hosts/elevate", s.handleElevate)
	s.mux.HandleFunc("/api/hosts/rotate", s.handleRotateHost)
	s.mux.HandleFunc("/api/hosts/rotate-all", s.handleRotateAllHosts)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.Handle("/metrics", promhttp.Handler())
	s.mux.HandleFunc("/api/onetap/", s.handleOneTap)
	s.mux.HandleFunc("/theme", s.handleThemeToggle)
	s.mux.HandleFunc("/signout", s.handleSignOut)
	s.mux.HandleFunc("/install.sh", s.handleInstallScript)
	// Dashboard is the catch-all — register AFTER all other routes.
	s.mux.HandleFunc("/", s.handleDashboard)

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

