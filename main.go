package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
)

// messageWriter is where PAM messages are written. pam_exec sends stdout to
// the user's terminal. We default to os.Stdout but allow override for testing.
var messageWriter io.Writer = os.Stdout

// safeUsername validates the PAM_USER value to prevent injection attacks.
// PAM usernames should be short, alphanumeric with limited special chars.
var safeUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		runServer()
	} else {
		runPAMHelper()
	}
}

func runServer() {
	cfg, err := LoadServerConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	if cfg.SharedSecret == "" {
		log.Printf("WARNING: PAM_POCKETID_SHARED_SECRET is not set - API endpoints are unauthenticated!")
	}

	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("server init error: %v", err)
	}

	log.Printf("pam-pocketid server listening on %s", cfg.ListenAddr)
	log.Printf("External URL: %s", cfg.ExternalURL)
	log.Printf("OIDC issuer: %s", cfg.IssuerURL)
	log.Printf("Challenge TTL: %s", cfg.ChallengeTTL)

	if err := http.ListenAndServe(cfg.ListenAddr, srv); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func runPAMHelper() {
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

	client := NewPAMClient(cfg)
	if err := client.Authenticate(username); err != nil {
		fmt.Fprintf(os.Stderr, "pam-pocketid: %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
