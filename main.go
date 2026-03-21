package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// messageWriter is where PAM messages are written. pam_exec sends stdout to
// the user's terminal. We default to os.Stdout but allow override for testing.
var messageWriter io.Writer = os.Stdout

// version is set at build time via -ldflags "-X main.version=v0.6.1".
var version = "dev"

// safeUsername validates the PAM_USER value to prevent injection attacks.
// PAM usernames should be short, alphanumeric with limited special chars.
var safeUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Println(version)
			os.Exit(0)
		case "--help", "-h", "help":
			fmt.Printf("pam-pocketid %s — browser-based sudo authentication via Pocket ID\n", version)
			fmt.Print(`
Usage:
  pam-pocketid                   PAM helper (called by pam_exec)
  pam-pocketid serve             Run the authentication server
  pam-pocketid rotate-breakglass Rotate the break-glass password
  pam-pocketid verify-breakglass Verify a break-glass password
  pam-pocketid --version         Show version
  pam-pocketid --help            Show this help message
`)
			os.Exit(0)
		case "serve":
			runServer()
			return
		case "rotate-breakglass":
			runRotateBreakglass()
			return
		case "verify-breakglass":
			runVerifyBreakglass()
			return
		}
	}
	runPAMHelper()
}

func runServer() {
	cfg, err := LoadServerConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("server init error: %v", err)
	}

	log.Printf("pam-pocketid server listening on %s", cfg.ListenAddr)
	log.Printf("External URL: %s", cfg.ExternalURL)
	log.Printf("OIDC issuer: %s", cfg.IssuerURL)
	log.Printf("OIDC redirect URI: %s/callback", cfg.ExternalURL)
	log.Printf("Challenge TTL: %s", cfg.ChallengeTTL)
	if cfg.GracePeriod > 0 {
		log.Printf("Grace period: %s (sudo re-auth skipped within this window)", cfg.GracePeriod)
	}
	if cfg.SessionStateFile != "" {
		log.Printf("Session persistence: %s", cfg.SessionStateFile)
	}
	if cfg.NotifyCommand != "" {
		log.Printf("Notify command configured (push notifications enabled)")
		if cfg.NotifyUsersFile != "" {
			log.Printf("Per-user notification routing: %s", cfg.NotifyUsersFile)
		}
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8192,
	}

	// Graceful shutdown: drain in-flight requests, wait for notifications, stop reaper.
	// The shutdownDone channel ensures main waits for the full shutdown sequence
	// before returning (otherwise main exits as soon as ListenAndServe unblocks).
	shutdownDone := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		defer close(shutdownDone)
		sig := <-sigCh
		log.Printf("received %s, shutting down gracefully...", sig)
		// A second signal forces immediate exit (e.g., double Ctrl+C).
		go func() {
			sig2 := <-sigCh
			log.Printf("received second signal, forcing exit")
			if s, ok := sig2.(syscall.Signal); ok {
				os.Exit(128 + int(s))
			}
			os.Exit(1)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
		srv.WaitForNotifications(5 * time.Second)
		srv.store.SaveState()
		srv.Stop()
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	<-shutdownDone
	log.Printf("server stopped")
}

func runRotateBreakglass() {
	force := false
	for _, arg := range os.Args[2:] {
		switch arg {
		case "--force", "-f":
			force = true
		default:
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", arg)
			fmt.Fprintf(os.Stderr, "usage: pam-pocketid rotate-breakglass [--force]\n")
			os.Exit(1)
		}
	}

	// Security: strip PAM_POCKETID_* and proxy env vars (same as PAM helper)
	// to prevent env-based config injection when run via cron or wrapper scripts.
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "PAM_POCKETID_") {
			key, _, _ := strings.Cut(env, "=")
			os.Unsetenv(key)
		}
	}
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
	} {
		os.Unsetenv(key)
	}

	// Allow rotation without a server URL (local-only, no escrow)
	clientConfigAllowNoServer = true
	cfg, err := LoadClientConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	plaintext, err := rotateBreakglass(cfg, force)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if plaintext != "" {
		fmt.Fprintf(os.Stderr, "\n*** IMPORTANT: Break-glass password was NOT escrowed. Save it now! ***\n")
		fmt.Fprintln(os.Stdout, plaintext)
		fmt.Fprintf(os.Stderr, "*** Store this password securely. It will not be shown again. ***\n\n")
	}
}

func runVerifyBreakglass() {
	// Security: strip PAM_POCKETID_* and proxy env vars (same as other subcommands)
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "PAM_POCKETID_") {
			key, _, _ := strings.Cut(env, "=")
			os.Unsetenv(key)
		}
	}
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
	} {
		os.Unsetenv(key)
	}

	// Allow verification without a server URL (local-only check)
	clientConfigAllowNoServer = true
	cfg, err := LoadClientConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Read the break-glass hash file
	hash, err := readBreakglassHash(cfg.BreakglassFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Prompt for password via /dev/tty
	tty, err := openTTY()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open terminal: %v\n", err)
		os.Exit(1)
	}
	defer tty.Close()

	fmt.Fprintf(tty, "Break-glass password: ")
	password, err := readPasswordFn(int(tty.Fd()))
	fmt.Fprintf(tty, "\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading password: %v\n", err)
		os.Exit(1)
	}

	// Verify with bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(hash), password); err != nil {
		fmt.Fprintln(os.Stderr, "Break-glass password does NOT match")
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Break-glass password verified successfully")
	os.Exit(0)
}

func runPAMHelper() {
	// Security: strip PAM_POCKETID_* env vars that a user might inject.
	// When running under sudo, the environment is normally sanitized by sudo's
	// env_reset. However, if env_keep is misconfigured to preserve PAM_POCKETID_*
	// vars, a non-root user could override SERVER_URL (pointing to a malicious server),
	// BREAKGLASS_FILE (pointing to a controlled hash file), or SHARED_SECRET.
	// By unsetting these, we force the PAM helper to read config from the
	// root-owned config file only.
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "PAM_POCKETID_") {
			key, _, _ := strings.Cut(env, "=")
			os.Unsetenv(key)
		}
	}

	// Security: strip proxy env vars that could redirect HTTP requests through
	// an attacker-controlled proxy, leaking the shared secret (X-Shared-Secret header)
	// and break-glass passwords (escrow POST body), or enabling auth bypass by
	// making the server appear unreachable (triggering break-glass fallback).
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
	} {
		os.Unsetenv(key)
	}

	// pam_exec sets PAM_USER in the environment.
	// When called via pam_exec, PAM_USER is set by the PAM framework and cannot
	// be spoofed by the calling user. However, if someone runs this binary
	// directly (outside of PAM), they could set PAM_USER to anything.
	// The PAM module configuration (pam_exec.so) is the trust boundary here:
	// the binary itself cannot distinguish between a legitimate PAM invocation
	// and a direct execution. This is acceptable because:
	// 1. The binary only creates a *challenge* -- it doesn't grant sudo access
	// 2. The OIDC flow still requires the real user to authenticate
	// 3. An attacker running this directly could only create a challenge for
	//    a username, then they'd still need to complete OIDC auth as that user
	username := os.Getenv("PAM_USER")
	if username == "" {
		fmt.Fprintln(os.Stderr, "PAM_USER not set (must be called via pam_exec)")
		os.Exit(1)
	}

	// Validate username to prevent injection via crafted PAM_USER values
	if !safeUsername.MatchString(username) {
		fmt.Fprintln(os.Stderr, "pam-pocketid: invalid username format")
		os.Exit(1)
	}

	// PAM_TYPE indicates the PAM operation (auth, account, session, password)
	pamType := os.Getenv("PAM_TYPE")
	if pamType != "" && pamType != "auth" {
		// Only handle auth requests; silently succeed for others
		os.Exit(0)
	}

	cfg, err := LoadClientConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pam-pocketid config error: %v\n", err)
		os.Exit(1)
	}

	var cache *TokenCache
	if cfg.TokenCacheEnabled {
		cache = NewTokenCache(cfg.TokenCacheDir, cfg.TokenCacheIssuer, cfg.TokenCacheClientID)
	}

	client := NewPAMClient(cfg, cache)
	if err := client.Authenticate(username); err != nil {
		fmt.Fprintf(os.Stderr, "pam-pocketid: %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
