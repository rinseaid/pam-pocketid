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
  pam-pocketid                        PAM helper (called by pam_exec)
  pam-pocketid serve                  Run the authentication server
  pam-pocketid rotate-breakglass      Rotate the break-glass password
  pam-pocketid verify-breakglass      Verify a break-glass password
  pam-pocketid add-host <hostname>    Register a host (--users user1,user2 --group groupname)
  pam-pocketid remove-host <hostname> Unregister a host
  pam-pocketid list-hosts             List registered hosts
  pam-pocketid rotate-host-secret <hostname> Rotate a host's secret
  pam-pocketid --version              Show version
  pam-pocketid --help                 Show this help message
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
		case "add-host":
			runAddHost()
			return
		case "remove-host":
			runRemoveHost()
			return
		case "list-hosts":
			runListHosts()
			return
		case "rotate-host-secret":
			runRotateHostSecret()
			return
		}
	}
	// If there's an arg that looks like a subcommand but isn't recognized, show an error
	if len(os.Args) > 1 {
		knownArgs := map[string]bool{
			"--version": true, "-v": true, "version": true,
			"--help": true, "-h": true, "help": true,
			"serve": true, "rotate-breakglass": true, "verify-breakglass": true,
			"add-host": true, "remove-host": true, "list-hosts": true,
			"rotate-host-secret": true,
		}
		if !strings.HasPrefix(os.Args[1], "-") && !knownArgs[os.Args[1]] {
			fmt.Fprintf(os.Stderr, "unknown command: %s\nRun 'pam-pocketid --help' for usage.\n", os.Args[1])
			os.Exit(1)
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
	if cfg.HostRegistryFile != "" {
		if srv.hostRegistry.IsEnabled() {
			log.Printf("Host registry: %s (%d hosts registered)", cfg.HostRegistryFile, len(srv.hostRegistry.RegisteredHosts()))
		} else {
			log.Printf("Host registry: %s (no hosts registered, using global shared secret)", cfg.HostRegistryFile)
		}
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
		WriteTimeout:      0, // disabled for SSE connections; per-handler timeouts used instead
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
	// Request SIGTERM when parent process dies (Linux only). This handles Ctrl+C
	// during sudo: SIGINT goes to sudo, sudo exits, kernel sends us SIGTERM.
	requestParentDeathSignal()

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

func runAddHost() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: pam-pocketid add-host <hostname> [--users user1,user2] [--group groupname]")
		os.Exit(1)
	}
	hostname := os.Args[2]
	if !validHostname.MatchString(hostname) {
		fmt.Fprintln(os.Stderr, "invalid hostname format")
		os.Exit(1)
	}

	// Parse --users and --group flags
	users := []string{"*"} // default: all users
	group := ""
	for i := 3; i < len(os.Args); i++ {
		if os.Args[i] == "--users" && i+1 < len(os.Args) {
			users = strings.Split(os.Args[i+1], ",")
			i++ // skip the value
		} else if os.Args[i] == "--group" && i+1 < len(os.Args) {
			group = os.Args[i+1]
			i++ // skip the value
		} else if strings.HasPrefix(os.Args[i], "-") {
			fmt.Fprintf(os.Stderr, "unknown flag: %s\nusage: pam-pocketid add-host <hostname> [--users user1,user2] [--group groupname]\n", os.Args[i])
			os.Exit(1)
		}
	}

	registryPath := os.Getenv("PAM_POCKETID_HOST_REGISTRY_FILE")
	if registryPath == "" {
		registryPath = "/data/hosts.json"
	}

	registry := NewHostRegistry(registryPath)
	secret, err := registry.AddHost(hostname, users, group)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Host %q registered successfully.\n", hostname)
	fmt.Fprintf(os.Stderr, "Authorized users: %s\n", strings.Join(users, ", "))
	if group != "" {
		fmt.Fprintf(os.Stderr, "Group: %s\n", group)
	}
	fmt.Fprintf(os.Stderr, "\nAdd this to /etc/pam-pocketid.conf on %s:\n", hostname)
	fmt.Fprintf(os.Stderr, "  PAM_POCKETID_SHARED_SECRET=%s\n\n", secret)
	// Also print just the secret to stdout for scripting
	fmt.Fprintln(os.Stdout, secret)
}

func runRemoveHost() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: pam-pocketid remove-host <hostname>")
		os.Exit(1)
	}
	hostname := os.Args[2]
	if !validHostname.MatchString(hostname) {
		fmt.Fprintln(os.Stderr, "invalid hostname format")
		os.Exit(1)
	}
	registryPath := os.Getenv("PAM_POCKETID_HOST_REGISTRY_FILE")
	if registryPath == "" {
		registryPath = "/data/hosts.json"
	}
	registry := NewHostRegistry(registryPath)
	if err := registry.RemoveHost(hostname); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Host %q removed.\n", hostname)
}

func runListHosts() {
	registryPath := os.Getenv("PAM_POCKETID_HOST_REGISTRY_FILE")
	if registryPath == "" {
		registryPath = "/data/hosts.json"
	}
	registry := NewHostRegistry(registryPath)
	hosts := registry.RegisteredHosts()
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "No hosts registered. All hosts accepted with global shared secret.")
		return
	}
	for _, h := range hosts {
		users, _, registeredAt, _ := registry.GetHost(h)
		fmt.Fprintf(os.Stdout, "%s  users=%s  registered=%s\n", h, strings.Join(users, ","), registeredAt.Format("2006-01-02"))
	}
}

func runRotateHostSecret() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: pam-pocketid rotate-host-secret <hostname>")
		os.Exit(1)
	}
	hostname := os.Args[2]
	if !validHostname.MatchString(hostname) {
		fmt.Fprintln(os.Stderr, "invalid hostname format")
		os.Exit(1)
	}
	registryPath := os.Getenv("PAM_POCKETID_HOST_REGISTRY_FILE")
	if registryPath == "" {
		registryPath = "/data/hosts.json"
	}
	registry := NewHostRegistry(registryPath)
	secret, err := registry.RotateSecret(hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Secret rotated for %q.\n", hostname)
	fmt.Fprintf(os.Stderr, "Update /etc/pam-pocketid.conf on %s:\n", hostname)
	fmt.Fprintf(os.Stderr, "  PAM_POCKETID_SHARED_SECRET=%s\n\n", secret)
	fmt.Fprintln(os.Stdout, secret)
}
