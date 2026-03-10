package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PAMClient is the helper that runs under pam_exec, creates a challenge,
// displays the approval URL, and polls until approved/denied/expired.
type PAMClient struct {
	cfg    *Config
	client *http.Client
}

// maxResponseSize limits how much of a server response we will read (64KB).
// Prevents a malicious/compromised server from causing OOM in the PAM helper.
const maxResponseSize = 64 * 1024

// NewPAMClient creates a new PAM helper client.
func NewPAMClient(cfg *Config) *PAMClient {
	return &PAMClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
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
	ChallengeID     string `json:"challenge_id"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
}

// pollResponse is the response from GET /api/challenge/{id}.
type pollResponse struct {
	Status    string `json:"status"`
	ExpiresIn int    `json:"expires_in"`
}

// Authenticate runs the full PAM authentication flow for the given username.
// Returns nil on success (sudo approved), non-nil on failure.
func (p *PAMClient) Authenticate(username string) error {
	// 1. Create challenge
	challenge, err := p.createChallenge(username)
	if err != nil {
		return fmt.Errorf("creating challenge: %w", err)
	}

	// 2. Display approval info to user.
	// SECURITY: We do NOT display the server-provided VerificationURL, because
	// a compromised server could return a phishing URL. Instead we display only
	// the user code. The user already knows their org's approval URL.
	fmt.Fprintf(messageWriter, "\n")
	fmt.Fprintf(messageWriter, "  Sudo elevation requires Pocket ID approval.\n")
	fmt.Fprintf(messageWriter, "  Code: %s\n", challenge.UserCode)
	if challenge.VerificationURL != "" {
		fmt.Fprintf(messageWriter, "  Approve at: %s\n", challenge.VerificationURL)
	}
	fmt.Fprintf(messageWriter, "\n")
	fmt.Fprintf(messageWriter, "  Waiting for approval (expires in %ds)...\n", challenge.ExpiresIn)

	// 3. Poll until resolved
	deadline := time.Now().Add(p.cfg.Timeout)
	for time.Now().Before(deadline) {
		time.Sleep(p.cfg.PollInterval)

		status, err := p.pollChallenge(challenge.ChallengeID)
		if err != nil {
			continue // transient error, keep polling
		}

		switch ChallengeStatus(status.Status) {
		case StatusApproved:
			fmt.Fprintf(messageWriter, "  Approved!\n\n")
			return nil
		case StatusDenied:
			return fmt.Errorf("sudo request denied")
		case StatusExpired:
			return fmt.Errorf("sudo request expired")
		case StatusPending:
			continue
		default:
			return fmt.Errorf("unexpected status: %s", status.Status)
		}
	}

	return fmt.Errorf("timed out waiting for approval")
}

func (p *PAMClient) createChallenge(username string) (*challengeResponse, error) {
	body, _ := json.Marshal(map[string]string{"username": username})
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
		// Limit how much of the error response we read
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}

	var cr challengeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
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

	var pr pollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&pr); err != nil {
		return nil, err
	}

	// 404 means expired
	if resp.StatusCode == http.StatusNotFound {
		pr.Status = string(StatusExpired)
	}

	return &pr, nil
}
