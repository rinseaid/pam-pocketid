package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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
	expiry := time.Now().Add(s.store.GraceRemaining(challenge.Username, challenge.Hostname))
	setFlashCookie(w, fmt.Sprintf("approved:%s:%s:%d", hostname, challenge.Username, expiry.Unix()))
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
}

// handleOneTap processes a one-tap approval link from a notification.
// GET /api/onetap/{token}
//
// NOTE: One-tap URLs are GET requests that approve challenges. Link previewers
// (Slack, Discord, iMessage) may fetch these URLs automatically. When OIDC is
// fresh (within OneTapMaxAge), this results in auto-approval without user
// interaction. Operators should ensure notification channels are trusted and
// consider reducing OneTapMaxAge to minimize the window. A POST-based
// confirmation step would eliminate this risk but degrade the one-tap UX.
func (s *Server) handleOneTap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.cfg.SharedSecret == "" {
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
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
		secure := strings.HasPrefix(s.cfg.ExternalURL, "https://")
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_onetap",
			Value:    token,
			Path:     "/",
			MaxAge:   300, // 5 minutes
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
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
	s.broadcastSSE(challenge.Username, "challenge_resolved")
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
	setFlashCookie(w, fmt.Sprintf("revoked:%s:%s", displayHostname, sessionOwner))
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

	var sessions []GraceSession
	targetUser := username
	if s.getSessionRole(r) == "admin" {
		if su := r.FormValue("session_username"); su != "" && validUsername.MatchString(su) {
			targetUser = su
			sessions = s.store.ActiveSessions(targetUser)
		} else {
			// Admin revoke-all without specific user: revoke all active sessions across all users
			sessions = s.store.AllActiveSessions()
			targetUser = ""
		}
	} else {
		sessions = s.store.ActiveSessions(targetUser)
	}

	// Revoke all collected sessions
	notified := make(map[string]bool)
	count := 0
	for _, sess := range sessions {
		sessUser := targetUser
		if sessUser == "" {
			sessUser = sess.Username
		}
		hostname := sess.Hostname
		if hostname == "(unknown)" {
			hostname = ""
		}
		s.store.RevokeSession(sessUser, hostname)
		s.store.LogAction(sessUser, "revoked", sess.Hostname, "", username)
		log.Printf("BULK_REVOKE_ALL: user %q host %q from %s", sessUser, sess.Hostname, remoteAddr(r))
		count++
		if !notified[sessUser] {
			s.broadcastSSE(sessUser, "session_changed")
			notified[sessUser] = true
		}
	}
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
	actor := s.verifyFormAuth(w, r)
	if actor == "" {
		return
	}
	// Admin may extend another user's session via a "session_username" form field.
	username := actor
	if s.getSessionRole(r) == "admin" {
		if su := r.FormValue("session_username"); su != "" && validUsername.MatchString(su) {
			username = su
		}
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

	// Always force-extend to max grace period — the user made an explicit action.
	remaining := s.store.ForceExtendGraceSession(username, hostname)
	if remaining == 0 {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	displayHostname := hostname
	if displayHostname == "" {
		displayHostname = "(unknown)"
	}
	s.store.LogAction(username, "extended", displayHostname, "", actor)
	log.Printf("EXTENDED: user %q host %q to %s from %s", username, displayHostname, remaining, remoteAddr(r))
	s.broadcastSSE(username, "session_changed")

	dest := r.FormValue("from")
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") {
		dest = "/"
	}
	expiry := time.Now().Add(remaining)
	setFlashCookie(w, fmt.Sprintf("extended:%s:%s:%d", displayHostname, username, expiry.Unix()))
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
	targetUser := username
	if s.getSessionRole(r) == "admin" {
		if su := r.FormValue("session_username"); su != "" && validUsername.MatchString(su) {
			targetUser = su
		}
	}
	sessions := s.store.ActiveSessions(targetUser)
	count := 0
	for _, sess := range sessions {
		hostname := sess.Hostname
		if hostname == "(unknown)" {
			hostname = ""
		}
		if s.store.ForceExtendGraceSession(targetUser, hostname) > 0 {
			s.store.LogAction(targetUser, "extended", sess.Hostname, "", username)
			count++
		}
	}
	s.broadcastSSE(targetUser, "session_changed")
	log.Printf("BULK_EXTEND_ALL: user %q extended %d sessions for %q from %s", username, count, targetUser, remoteAddr(r))

	expiry := time.Now().Add(s.cfg.GracePeriod)
	setFlashCookie(w, fmt.Sprintf("extended_all:%d:%d", count, expiry.Unix()))
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

	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
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

	// Admin may elevate a different user; fall back to self if not specified.
	targetUser := r.FormValue("target_user")
	if targetUser == "" {
		targetUser = username
	}
	if !validUsername.MatchString(targetUser) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Verify target user is authorized for this host
	if s.hostRegistry.IsEnabled() && !s.hostRegistry.IsUserAuthorized(hostname, targetUser) {
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

	s.store.CreateGraceSession(targetUser, hostname, duration)
	s.store.LogAction(targetUser, "elevated", hostname, "", username)
	log.Printf("ELEVATED: user %q host %q duration %s by %q from %s", targetUser, hostname, duration, username, remoteAddr(r))
	s.broadcastSSE(targetUser, "session_changed")

	expiry := time.Now().Add(duration)
	setFlashCookie(w, fmt.Sprintf("elevated:%s:%s:%d", hostname, targetUser, expiry.Unix()))
	from := r.FormValue("from")
	if from == "" || !strings.HasPrefix(from, "/") || strings.HasPrefix(from, "//") || strings.ContainsAny(from, "?#\\") {
		from = "/admin/hosts"
	}
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+from, http.StatusSeeOther)
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
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
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
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/admin/hosts", http.StatusSeeOther)
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
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
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
	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/admin/hosts", http.StatusSeeOther)
}
