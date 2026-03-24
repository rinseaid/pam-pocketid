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
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

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

	// Auto-approve if within grace period, but only for hosts that don't require admin approval.
	if s.store.WithinGracePeriod(req.Username, req.Hostname) && !s.requiresAdminApproval(req.Hostname) {
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
