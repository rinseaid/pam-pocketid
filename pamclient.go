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

// challengeResponse is the response from POST /api/challenge.
type challengeResponse struct {
	ChallengeID            string `json:"challenge_id"`
	UserCode               string `json:"user_code"`
	VerificationURL        string `json:"verification_url"`
	ExpiresIn              int    `json:"expires_in"`
	Status                 string `json:"status,omitempty"`
	ApprovalToken          string `json:"approval_token,omitempty"`
	RotateBreakglassBefore string `json:"rotate_breakglass_before,omitempty"`
	NotificationSent       bool   `json:"notification_sent,omitempty"`
	GraceRemaining         int    `json:"grace_remaining,omitempty"`
}

// pollResponse is the response from GET /api/challenge/{id}.
type pollResponse struct {
	Status        string `json:"status"`
	ExpiresIn     int    `json:"expires_in"`
	ApprovalToken string `json:"approval_token,omitempty"`
	DenialToken   string `json:"denial_token,omitempty"`
	IDToken       string `json:"id_token,omitempty"`

	// serverExpired is set locally when the server returns 404 (not from JSON).
	// Used to distinguish server-reported expiry from HMAC-verified status.
	serverExpired bool `json:"-"`
}

// Authenticate runs the full PAM authentication flow for the given username.
// Returns nil on success (sudo approved), non-nil on failure.
func (p *PAMClient) Authenticate(username string) error {
	// Set up signal handling so Ctrl+C produces a clean message.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintf(messageWriter, "\n  Cancelled.\n")
			os.Exit(1)
		case <-ctx.Done():
		}
	}()
	defer signal.Stop(sigCh)

	// 0. Check token cache — if a cached id_token is valid, grant immediately (no network call)
	if p.tokenCache != nil {
		if remaining, err := p.tokenCache.Check(username); err == nil {
			fmt.Fprintf(messageWriter, "  Sudo approved (session expires in %s)\n", formatDuration(remaining))
			// Still run break-glass age-based rotation check (no server signal
			// available since we didn't contact the server, so rotateBefore is zero).
			maybeRotateBreakglass(p.cfg, time.Time{})
			return nil
		}
		// Cache miss or invalid — fall through to device flow
	}

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
			if !p.verifyStatusToken(challenge.ChallengeID, username, "approved", challenge.ApprovalToken, challenge.RotateBreakglassBefore) {
				return fmt.Errorf("auto-approval token verification failed (possible MITM attack)")
			}
		}
		if challenge.GraceRemaining > 0 {
			fmt.Fprintf(messageWriter, "  Sudo approved (next auth in %s)\n", formatDuration(time.Duration(challenge.GraceRemaining)*time.Second))
		} else {
			fmt.Fprintf(messageWriter, "  Sudo approved\n")
		}
		maybeRotateBreakglass(p.cfg, rotateBefore)
		return nil
	}

	// 3. Display approval info to user.
	// Sanitize all server-provided values before terminal display to prevent
	// ANSI escape injection from a compromised server.
	fmt.Fprintf(messageWriter, "  Sudo requires Pocket ID approval.\n")
	if challenge.VerificationURL != "" {
		fmt.Fprintf(messageWriter, "  Approve at: %s\n", sanitizeForTerminal(challenge.VerificationURL))
	}
	fmt.Fprintf(messageWriter, "  Code: %s", sanitizeForTerminal(challenge.UserCode))
	if challenge.NotificationSent {
		fmt.Fprintf(messageWriter, " (notification sent)")
	}
	fmt.Fprintf(messageWriter, "\n")
	fmt.Fprintf(messageWriter, "  Waiting for approval...")

	// 4. Poll until resolved
	if p.cfg.SharedSecret == "" {
		fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: no shared secret configured — HMAC verification disabled\n")
	}

	var consecutiveErrors int
	var pollCount int
	deadline := time.Now().Add(p.cfg.Timeout)
	// Initial delay before first poll — the challenge was just created,
	// give the user a moment to start the approval flow.
	if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
		return err
	}

	for time.Now().Before(deadline) {
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
				fmt.Fprintf(messageWriter, "\n  Server became unreachable during approval.\n")
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
				if !p.verifyStatusToken(challenge.ChallengeID, username, "approved", status.ApprovalToken, challenge.RotateBreakglassBefore) {
					return fmt.Errorf("approval token verification failed (possible MITM attack)")
				}
			}
			// Cache the id_token for future authentication without device flow
			if p.tokenCache != nil && status.IDToken != "" {
				if err := p.tokenCache.Write(username, status.IDToken); err != nil {
					fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: failed to cache token: %v\n", err)
				}
			}
			fmt.Fprintf(messageWriter, " Approved!\n")
			maybeRotateBreakglass(p.cfg, rotateBefore)
			return nil
		case StatusDenied:
			// Verify HMAC denial token to prevent MITM injecting fake denials.
			// If verification fails, treat as a forged response and keep polling.
			// We never accept unverified denials — a MITM should not be able to
			// deny sudo requests by injecting fake denial responses.
			if p.cfg.SharedSecret != "" {
				if !p.verifyStatusToken(challenge.ChallengeID, username, "denied", status.DenialToken, challenge.RotateBreakglassBefore) {
					fmt.Fprintf(os.Stderr, "pam-pocketid: WARNING: denial token verification failed — ignoring possible forged denial\n")
					if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
						return err
					}
					continue
				}
			}
			fmt.Fprintf(messageWriter, " Denied.\n")
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
			fmt.Fprintf(messageWriter, " Expired.\n")
			return fmt.Errorf("sudo request expired")
		case StatusPending:
			// Poll again after interval
		default:
			return fmt.Errorf("unexpected status: %s", sanitizeForTerminal(status.Status))
		}

		pollCount++
		if pollCount%5 == 0 {
			fmt.Fprintf(messageWriter, ".")
		}
		if err := sleepWithContext(ctx, p.cfg.PollInterval); err != nil {
			return err
		}
	}

	fmt.Fprintf(messageWriter, " Expired.\n")
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

// verifyStatusToken verifies an HMAC-SHA256 status token from the server.
// The status parameter must match what the server used (e.g., "approved", "denied").
// Uses length-prefixed fields to match the server's computeStatusHMAC format.
// rotateBefore is included in the HMAC to prevent a MITM from injecting
// rotate_breakglass_before without invalidating the token.
func (p *PAMClient) verifyStatusToken(challengeID, username, status, token, rotateBefore string) bool {
	if token == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(p.cfg.SharedSecret))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(challengeID), challengeID, len(status), status, len(username), username)
	if rotateBefore != "" {
		fmt.Fprintf(mac, "%d:%s", len(rotateBefore), rotateBefore)
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
