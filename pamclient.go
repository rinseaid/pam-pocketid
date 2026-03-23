package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// validChallengeID validates that a challenge ID from the server is a 32-char hex string,
// preventing path traversal or query injection when used in poll URLs.
var validChallengeID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// PAMClient is the helper that runs under pam_exec, creates a challenge,
// displays the approval URL, and polls until approved/denied/expired.
type PAMClient struct {
	cfg        *Config
	client     *http.Client
	tokenCache *TokenCache
}

// maxResponseSize limits how much of a server response we will read (64KB).
// Prevents a malicious/compromised server from causing OOM in the PAM helper.
const maxResponseSize = 64 * 1024

// serverHTTPError represents an HTTP error from a reachable server.
// Distinguished from connection-level errors to control break-glass fallback:
// server returned an HTTP response (even an error) → server is reachable → no fallback.
type serverHTTPError struct {
	StatusCode int
	Body       string
}

func (e *serverHTTPError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.StatusCode, e.Body)
}

// NewPAMClient creates a new PAM helper client.
func NewPAMClient(cfg *Config, tokenCache *TokenCache) *PAMClient {
	return &PAMClient{
		cfg:        cfg,
		tokenCache: tokenCache,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// Never use proxy env vars — prevents an attacker from routing
				// requests through a malicious proxy via HTTP_PROXY/HTTPS_PROXY.
				Proxy: nil,
				// Explicit dial timeout (shorter than client Timeout) ensures that
				// connection-phase failures (SYN dropped by firewall) always produce
				// net.OpError{Op:"dial"} rather than racing with the client-level
				// timeout. This makes isServerUnreachable detection reliable.
				DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
			// Do not follow redirects. The PAM client talks to a known API server;
			// following redirects could enable SSRF if the server URL is misconfigured
			// or if a MITM redirects to internal services.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// clientConfigResponse is the server-side client config override.
type clientConfigResponse struct {
	BreakglassPasswordType string `json:"breakglass_password_type,omitempty"`
	BreakglassRotationDays int    `json:"breakglass_rotation_days,omitempty"`
	TokenCacheEnabled      *bool  `json:"token_cache_enabled,omitempty"`
}

// challengeResponse is the response from POST /api/challenge.
type challengeResponse struct {
	ChallengeID            string                `json:"challenge_id"`
	UserCode               string                `json:"user_code"`
	VerificationURL        string                `json:"verification_url"`
	ExpiresIn              int                   `json:"expires_in"`
	Status                 string                `json:"status,omitempty"`
	ApprovalToken          string                `json:"approval_token,omitempty"`
	RotateBreakglassBefore string                `json:"rotate_breakglass_before,omitempty"`
	RevokeTokensBefore     string                `json:"revoke_tokens_before,omitempty"`
	NotificationSent       bool                  `json:"notification_sent,omitempty"`
	GraceRemaining         int                   `json:"grace_remaining,omitempty"`
	ClientConfig           *clientConfigResponse  `json:"client_config,omitempty"`
}

// pollResponse is the response from GET /api/challenge/{id}.
type pollResponse struct {
	Status         string `json:"status"`
	ExpiresIn      int    `json:"expires_in"`
	ApprovalToken  string `json:"approval_token,omitempty"`
	DenialToken    string `json:"denial_token,omitempty"`
	IDToken        string `json:"id_token,omitempty"`
	GraceRemaining int    `json:"grace_remaining,omitempty"`

	// serverExpired is set locally when the server returns 404 (not from JSON).
	// Used to distinguish server-reported expiry from HMAC-verified status.
	serverExpired bool `json:"-"`
}

// Authenticate runs the full PAM authentication flow for the given username.
// Returns nil on success (sudo approved), non-nil on failure.
func (p *PAMClient) Authenticate(username string) error {
	// Detect terminal language for user-facing messages
	t := T(terminalLang())
	// Set up signal handling so Ctrl+C exits cleanly.
	// Write to stderr (not stdout/messageWriter) because the PAM conversation
	// pipe on stdout may have a full buffer, causing fmt.Fprintf to block
	// indefinitely and preventing os.Exit from ever being reached.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "pam-pocketid: interrupted")
			os.Exit(1)
		case <-ctx.Done():
		}
	}()
	defer signal.Stop(sigCh)

	// 0. Check token cache — if a cached id_token is valid, grant access.
	// Also check the server for revocation signals — a revoked session takes
	// precedence over the token cache.
	if p.tokenCache != nil {
		if tokenRemaining, err := p.tokenCache.Check(username); err == nil {
			// Check server for revocation and grace period (best-effort, 2s timeout)
			graceStatus := p.queryGraceStatus(username)

			// If the server reports a revocation that postdates our cache, invalidate it
			if graceStatus.revoked {
				if mtime, err := p.tokenCache.ModTime(username); err == nil {
					if mtime.Before(graceStatus.revokeTime) {
						p.tokenCache.Delete(username)
						// Fall through to device flow
						goto deviceFlow
					}
				}
			}

			// Show the effective remaining time (max of token and grace)
			effective := tokenRemaining
			if graceStatus.graceRemaining > effective {
				effective = graceStatus.graceRemaining
			}
			fmt.Fprintf(messageWriter, "  "+t("terminal_sudo_approved")+"\n", formatDuration(effective))
			// Still run break-glass age-based rotation check (no server signal
			// available since we didn't contact the server, so rotateBefore is zero).
			maybeRotateBreakglass(p.cfg, time.Time{})
			return nil
		}
		// Cache miss or invalid — fall through to device flow
	}

deviceFlow:

	// 1. Create challenge
	challenge, err := p.createChallenge(username)
	if err != nil {
		// Break-glass fallback: if the server is unreachable and a break-glass
		// hash file exists, fall back to local password authentication.
		if p.cfg.BreakglassEnabled && breakglassFileExists(p.cfg.BreakglassFile) && isServerUnreachable(err) {
			return authenticateBreakglass(username, p.cfg.BreakglassFile)
		}
		return fmt.Errorf("creating challenge: %w", err)
	}

	// Parse server-requested rotation timestamp (if any).
	// Only acted on after HMAC verification (the field is included in the HMAC),
	// so a MITM cannot inject a rotation signal without invalidating the token.
	var rotateBefore time.Time
	if challenge.RotateBreakglassBefore != "" {
		if t, err := time.Parse(time.RFC3339, challenge.RotateBreakglassBefore); err == nil {
			rotateBefore = t
		}
	}

	// 2. Check if auto-approved via grace period
	if challenge.Status == string(StatusApproved) {
		if p.cfg.SharedSecret != "" {
			if !p.verifyStatusToken(challenge.ChallengeID, username, "approved", challenge.ApprovalToken, challenge.RotateBreakglassBefore, challenge.RevokeTokensBefore) {
				return fmt.Errorf("auto-approval token verification failed (possible MITM attack)")
			}
		}

		// Apply server-side client config overrides AFTER HMAC verification.
		// client_config is not HMAC-protected, so a MITM could inject it —
		// but only after the approval token is verified, limiting the window
		// to authenticated (non-forged) responses.
		applyClientConfig(p, challenge)

		// Handle cache invalidation signal after HMAC verification
		handleCacheInvalidation(p, challenge, username)
		if challenge.GraceRemaining > 0 {
			fmt.Fprintf(messageWriter, "  "+t("terminal_sudo_approved")+"\n", formatDuration(time.Duration(challenge.GraceRemaining)*time.Second))
		} else {
			fmt.Fprintf(messageWriter, "  %s\n", t("terminal_sudo_approved_short"))
		}
		maybeRotateBreakglass(p.cfg, rotateBefore)
		return nil
	}

	// 3. Display approval info to user.
	// Sanitize all server-provided values before terminal display to prevent
	// ANSI escape injection from a compromised server.
	fmt.Fprintf(messageWriter, "  %s\n", t("terminal_requires_approval"))
	if challenge.VerificationURL != "" {
		fmt.Fprintf(messageWriter, "  %s %s\n", t("terminal_approve_at"), sanitizeForTerminal(challenge.VerificationURL))
	}
	fmt.Fprintf(messageWriter, "  %s %s", t("terminal_code"), sanitizeForTerminal(challenge.UserCode))
	if challenge.NotificationSent {
		fmt.Fprintf(messageWriter, " %s", t("terminal_notification_sent"))
	}
	fmt.Fprintf(messageWriter, "\n")

	// 4. Poll until resolved
	if p.cfg.SharedSecret == "" {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: no shared secret configured — HMAC verification disabled\n")
	}

	var consecutiveErrors int
	deadline := time.Now().Add(p.cfg.Timeout)

	// Initial delay before first poll — the challenge was just created,
	// give the user a moment to start the approval flow.
	if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
		return err
	}

	ppid := os.Getppid()
	for time.Now().Before(deadline) {
		// Check if parent process died (e.g., sudo killed by Ctrl+C).
		// On Linux, PR_SET_PDEATHSIG handles this faster, but this
		// is a portable fallback for macOS and other systems.
		if os.Getppid() != ppid {
			fmt.Fprintln(os.Stderr, "pam-pocketid: parent process died, exiting")
			os.Exit(1)
		}

		status, err := p.pollChallenge(challenge.ChallengeID)
		if err != nil {
			consecutiveErrors++
			// Log first error and every 10th to avoid flooding
			if consecutiveErrors == 1 || consecutiveErrors%10 == 0 {
				fmt.Fprintf(os.Stderr, "pam-pocketid: poll error (%d consecutive): %v\n", consecutiveErrors, err)
			}
			// Break-glass fallback: if server becomes unreachable during polling
			if consecutiveErrors > 5 && isServerUnreachable(err) &&
				p.cfg.BreakglassEnabled && breakglassFileExists(p.cfg.BreakglassFile) {
				fmt.Fprintf(messageWriter, "  %s\n", t("terminal_server_unreachable"))
				return authenticateBreakglass(username, p.cfg.BreakglassFile)
			}
			if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
				return err
			}
			continue
		}
		consecutiveErrors = 0

		switch ChallengeStatus(status.Status) {
		case StatusApproved:
			// Verify HMAC approval token to prevent MITM forgery
			if p.cfg.SharedSecret != "" {
				if !p.verifyStatusToken(challenge.ChallengeID, username, "approved", status.ApprovalToken, challenge.RotateBreakglassBefore, challenge.RevokeTokensBefore) {
					return fmt.Errorf("approval token verification failed (possible MITM attack)")
				}
			}
			// Cache the id_token for future authentication without device flow
			if p.tokenCache != nil && status.IDToken != "" {
				if err := p.tokenCache.Write(username, status.IDToken); err != nil {
					fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: failed to cache token: %v\n", err)
				}
			}
			fmt.Fprintf(messageWriter, "  %s\n", t("terminal_approved"))
			maybeRotateBreakglass(p.cfg, rotateBefore)
			return nil
		case StatusDenied:
			// Verify HMAC denial token to prevent MITM injecting fake denials.
			// If verification fails, treat as a forged response and keep polling.
			// We never accept unverified denials — a MITM should not be able to
			// deny sudo requests by injecting fake denial responses.
			if p.cfg.SharedSecret != "" {
				if !p.verifyStatusToken(challenge.ChallengeID, username, "denied", status.DenialToken, challenge.RotateBreakglassBefore, challenge.RevokeTokensBefore) {
					fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: denial token verification failed — ignoring possible forged denial\n")
					if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
						return err
					}
					continue
				}
			}
			fmt.Fprintf(messageWriter, "  %s\n", t("terminal_denied"))
			return fmt.Errorf("sudo request denied")
		case StatusExpired:
			// When HMAC is configured, don't trust ANY unverified expiry.
			// A MITM could inject 404 or {"status":"expired"} as a 200
			// response to block sudo approvals. Keep polling until our
			// own client-side timeout (cfg.Timeout) expires instead.
			if p.cfg.SharedSecret != "" {
				fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: ignoring unverified expiry — continuing to poll until client timeout\n")
				if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
					return err
				}
				continue
			}
			fmt.Fprintf(messageWriter, "  %s\n", t("terminal_expired"))
			return fmt.Errorf("sudo request expired")
		case StatusPending:
			// Poll again after interval
		default:
			return fmt.Errorf("unexpected status: %s", sanitizeForTerminal(status.Status))
		}

		if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
			return err
		}
	}

	fmt.Fprintf(messageWriter, "  %s\n", t("terminal_expired"))
	return fmt.Errorf("timed out waiting for approval")
}

// sleepWithContext sleeps for the given duration but returns early if ctx is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// graceStatusResult holds the response from the grace status endpoint.
type graceStatusResult struct {
	graceRemaining time.Duration
	revoked        bool
	revokeTime     time.Time
}

// queryGraceStatus makes a quick call to the server to get the grace period
// remaining and any revocation signal. Returns a zero result on any failure
// (server unreachable, timeout, error). On cache hits, a revocation signal
// takes precedence over the cached token — the cache is deleted and the
// client falls through to the device flow.
func (p *PAMClient) queryGraceStatus(username string) graceStatusResult {
	if p.cfg.ServerURL == "" {
		return graceStatusResult{}
	}
	hostname, _ := os.Hostname()
	u := fmt.Sprintf("%s/api/grace-status", p.cfg.ServerURL)
	params := "?username=" + neturl.QueryEscape(username) + "&hostname=" + neturl.QueryEscape(hostname)
	url := u + params
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return graceStatusResult{}
	}
	if p.cfg.SharedSecret != "" {
		req.Header.Set("X-Shared-Secret", p.cfg.SharedSecret)
	}
	// Short timeout — revocation check is critical but must not block sudo indefinitely.
	// Hardened like the main client: no proxy, no redirect following.
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return graceStatusResult{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return graceStatusResult{}
	}
	var result struct {
		GraceRemaining     int    `json:"grace_remaining"`
		RevokeTokensBefore string `json:"revoke_tokens_before,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512)).Decode(&result); err != nil {
		return graceStatusResult{}
	}
	gs := graceStatusResult{
		graceRemaining: time.Duration(result.GraceRemaining) * time.Second,
	}
	if result.RevokeTokensBefore != "" {
		if t, err := time.Parse(time.RFC3339, result.RevokeTokensBefore); err == nil {
			gs.revoked = true
			gs.revokeTime = t
		}
	}
	return gs
}

// applyClientConfig applies server-side config overrides to the PAM client.
// Called AFTER HMAC verification to prevent MITM injection of config values.
func applyClientConfig(p *PAMClient, challenge *challengeResponse) {
	if challenge.ClientConfig == nil {
		return
	}
	if challenge.ClientConfig.BreakglassPasswordType != "" {
		p.cfg.BreakglassPasswordType = challenge.ClientConfig.BreakglassPasswordType
	}
	if challenge.ClientConfig.BreakglassRotationDays > 0 {
		p.cfg.BreakglassRotationDays = challenge.ClientConfig.BreakglassRotationDays
	}
	if challenge.ClientConfig.TokenCacheEnabled != nil {
		p.cfg.TokenCacheEnabled = *challenge.ClientConfig.TokenCacheEnabled
		if !p.cfg.TokenCacheEnabled {
			p.tokenCache = nil
		}
	}
}

// handleCacheInvalidation deletes the token cache if the server sent a revocation signal.
func handleCacheInvalidation(p *PAMClient, challenge *challengeResponse, username string) {
	if challenge.RevokeTokensBefore == "" || p.tokenCache == nil {
		return
	}
	if revokeTime, err := time.Parse(time.RFC3339, challenge.RevokeTokensBefore); err == nil {
		if mtime, err := p.tokenCache.ModTime(username); err == nil {
			if mtime.Before(revokeTime) {
				p.tokenCache.Delete(username)
			}
		}
	}
}

// verifyStatusToken verifies an HMAC-SHA256 status token from the server.
// The status parameter must match what the server used (e.g., "approved", "denied").
// Uses length-prefixed fields to match the server's computeStatusHMAC format.
// rotateBefore and revokeTokensBefore are included in the HMAC to prevent a MITM
// from injecting these signals without invalidating the token.
func (p *PAMClient) verifyStatusToken(challengeID, username, status, token, rotateBefore, revokeTokensBefore string) bool {
	if token == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(p.cfg.SharedSecret))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(challengeID), challengeID, len(status), status, len(username), username)
	if rotateBefore != "" {
		fmt.Fprintf(mac, "%d:%s", len(rotateBefore), rotateBefore)
	}
	if revokeTokensBefore != "" {
		fmt.Fprintf(mac, "r%d:%s", len(revokeTokensBefore), revokeTokensBefore)
	}
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(token))
}

func (p *PAMClient) createChallenge(username string) (*challengeResponse, error) {
	hostname, _ := os.Hostname()
	payload := map[string]string{"username": username}
	if hostname != "" {
		payload["hostname"] = hostname
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, p.cfg.ServerURL+"/api/challenge", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.SharedSecret != "" {
		req.Header.Set("X-Shared-Secret", p.cfg.SharedSecret)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to auth server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Limit how much of the error response we read and sanitize for terminal safety
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		safe := sanitizeForTerminal(string(b))
		return nil, &serverHTTPError{StatusCode: resp.StatusCode, Body: safe}
	}

	var cr challengeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Validate challenge ID format to prevent path traversal or query injection
	// if a compromised server returns a malicious challenge ID.
	if !validChallengeID.MatchString(cr.ChallengeID) {
		return nil, fmt.Errorf("server returned invalid challenge ID format")
	}

	return &cr, nil
}

func (p *PAMClient) pollChallenge(challengeID string) (*pollResponse, error) {
	req, err := http.NewRequest(http.MethodGet, p.cfg.ServerURL+"/api/challenge/"+challengeID, nil)
	if err != nil {
		return nil, err
	}
	if p.cfg.SharedSecret != "" {
		req.Header.Set("X-Shared-Secret", p.cfg.SharedSecret)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP status before trusting response body
	switch resp.StatusCode {
	case http.StatusOK:
		// normal — decode below
	case http.StatusNotFound:
		// When HMAC is configured, treat 404 as an unverified response.
		// A MITM could inject 404s to prevent the client from ever seeing
		// an "approved" response. Mark as server-expired (distinct from
		// client-side timeout) so the caller can handle it appropriately.
		return &pollResponse{Status: string(StatusExpired), serverExpired: true}, nil
	default:
		return nil, fmt.Errorf("poll returned HTTP %d", resp.StatusCode)
	}

	var pr pollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// formatDuration formats a duration as a human-readable string like "3h 12m" or "47m".
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 && m > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh", h)
	}
	if m > 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// sanitizeForTerminal removes control characters (ANSI escapes, null bytes, etc.)
// from a string before displaying it on a terminal.
// Also strips C1 control characters (U+0080-U+009F) which some terminals
// interpret as escape sequences (e.g., U+009B is CSI, equivalent to ESC[),
// and Unicode bidirectional override characters that could visually reorder text.
func sanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		// C1 control characters (U+0080-U+009F): some terminals interpret
		// U+009B as CSI (equivalent to ESC[), enabling escape injection
		if r >= 0x80 && r <= 0x9F {
			return -1
		}
		// Unicode bidirectional overrides and zero-width characters
		// that could visually disguise URLs or text
		if r >= 0x202A && r <= 0x202E { // LRE, RLE, PDF, LRO, RLO
			return -1
		}
		if r >= 0x2066 && r <= 0x2069 { // LRI, RLI, FSI, PDI
			return -1
		}
		if r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF { // zero-width chars, BOM
			return -1
		}
		return r
	}, s)
}
