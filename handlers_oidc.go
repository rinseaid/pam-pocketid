package main

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

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
	// Only store avatar URLs with safe schemes to prevent javascript: XSS.
	if p := claims.Picture; p != "" && (strings.HasPrefix(p, "https://") || strings.HasPrefix(p, "http://")) {
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_avatar",
			Value:    p,
			Path:     "/",
			MaxAge:   2592000, // 30 days — outlasts session cookie so avatar persists
			HttpOnly: false,   // needs to be readable for display
			SameSite: http.SameSiteLaxMode,
		})
	}

	// Check for pending one-tap approval after OIDC login.
	// If the pam_onetap cookie is present, the user was redirected here from
	// handleOneTap because their OIDC auth was stale. Now that they've
	// re-authenticated, resume the one-tap approval flow.
	if onetapCookie, err := r.Cookie("pam_onetap"); err == nil && onetapCookie.Value != "" {
		http.SetCookie(w, &http.Cookie{Name: "pam_onetap", Value: "", Path: "/", MaxAge: -1})
		// Verify the one-tap token's challenge belongs to the authenticated user
		parts := strings.SplitN(onetapCookie.Value, ".", 3)
		if len(parts) == 3 {
			if challenge, ok := s.store.Get(parts[0]); ok && challenge.Username == username {
				onetapURL := strings.TrimRight(s.cfg.ExternalURL, "/") + "/api/onetap/" + onetapCookie.Value
				http.Redirect(w, r, onetapURL, http.StatusSeeOther)
				return
			}
		}
		// Token invalid or challenge not for this user — fall through to dashboard
	}

	http.Redirect(w, r, strings.TrimRight(s.cfg.ExternalURL, "/")+"/", http.StatusSeeOther)
}

