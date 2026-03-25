package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"text/template"
	"time"
)

// notifyTimeout limits how long we wait for the notify command to complete.
const notifyTimeout = 15 * time.Second

// notifyMaxOutput caps the amount of stdout/stderr we read from the notify
// command to prevent a verbose or malicious command from exhausting memory.
const notifyMaxOutput = 1 << 20 // 1 MB

// notifyUsersMaxSize caps the size of the per-user notification JSON file
// to prevent memory exhaustion from an accidentally large file.
const notifyUsersMaxSize = 1 << 20 // 1 MB

// notifySemaphore limits concurrent notify command executions to prevent
// resource exhaustion if challenges arrive in bursts.
var notifySemaphore = make(chan struct{}, 10)

// loadNotifyUsers reads the per-user notification URL mapping from a JSON file.
// Returns nil map (not error) if the file doesn't exist or is empty — this is
// the normal case when per-user routing is not configured.
//
// Security: uses the same hardened file-reading pattern as loadConfigFile:
// O_NOFOLLOW to reject symlinks, fd-based stat for permissions/ownership
// (no TOCTOU gap), and size limit to prevent OOM.
func loadNotifyUsers(path string) map[string]string {
	if path == "" {
		return nil
	}

	// Open with O_NOFOLLOW to atomically reject symlinks.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("NOTIFY: cannot open users file %s: %v", path, err)
		}
		return nil
	}
	defer f.Close()

	// Use fd-based stat (not path-based) to avoid TOCTOU races.
	info, err := f.Stat()
	if err != nil {
		log.Printf("NOTIFY: cannot stat users file %s: %v", path, err)
		return nil
	}
	if !info.Mode().IsRegular() {
		log.Printf("NOTIFY: ERROR: %s is not a regular file — refusing to load", path)
		return nil
	}

	// Enforce size limit to prevent OOM from large files.
	if info.Size() > notifyUsersMaxSize {
		log.Printf("NOTIFY: ERROR: %s is too large (%d bytes, max %d) — refusing to load", path, info.Size(), notifyUsersMaxSize)
		return nil
	}

	// Enforce permissions: file may contain bot tokens and webhook secrets.
	if mode := info.Mode().Perm(); mode&0077 != 0 {
		log.Printf("NOTIFY: ERROR: %s has group/other permissions (mode %04o) — refusing to load (fix with: chmod 600 %s)", path, mode, path)
		return nil
	}

	// Enforce root ownership to prevent pre-creation attacks.
	if uid, ok := fileOwnerUID(info); !ok {
		log.Printf("NOTIFY: ERROR: cannot determine owner of %s — refusing to load", path)
		return nil
	} else if uid != 0 {
		log.Printf("NOTIFY: ERROR: %s is not owned by root (uid=%d) — refusing to load", path, uid)
		return nil
	}

	// Read from the already-opened fd (not the path) to maintain consistency.
	data, err := io.ReadAll(io.LimitReader(f, notifyUsersMaxSize+1))
	if err != nil {
		log.Printf("NOTIFY: cannot read users file %s: %v", path, err)
		return nil
	}

	// Strip UTF-8 BOM (common when edited on Windows).
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	// Empty file is valid — means no per-user routing configured.
	if len(data) == 0 {
		return nil
	}

	var users map[string]string
	if err := json.Unmarshal(data, &users); err != nil {
		log.Printf("NOTIFY: cannot parse users file %s: %v", path, err)
		return nil
	}
	return users
}

// lookupUserURLs returns the notification URL(s) for a username from the
// per-user mapping. Falls back to the "*" wildcard entry if the user has
// no explicit mapping. Returns empty string if no mapping exists.
func lookupUserURLs(users map[string]string, username string) string {
	if users == nil {
		return ""
	}
	if urls, ok := users[username]; ok {
		return urls
	}
	if urls, ok := users["*"]; ok {
		return urls
	}
	return ""
}

// sendNotification fires the configured notify command asynchronously when a
// new challenge is created. It is a no-op if no notify command is configured.
// Runs in a goroutine so it never blocks the challenge API response.
// The WaitGroup tracks in-flight goroutines for graceful shutdown.
func (s *Server) sendNotification(challenge *Challenge, approvalURL string, oneTapURL string) {
	if s.cfg.NotifyCommand == "" {
		return
	}

	// Capture values for the goroutine (challenge pointer may be mutated later).
	username := challenge.Username
	hostname := challenge.Hostname
	userCode := challenge.UserCode
	expiresIn := int(s.cfg.ChallengeTTL.Seconds())
	notifyCmd := s.cfg.NotifyCommand
	notifyEnv := s.cfg.NotifyEnvPassthrough
	notifyUsersFile := s.cfg.NotifyUsersFile
	notifyUsersInline := s.cfg.NotifyUsers

	s.notifyWg.Add(1)
	go func() {
		defer s.notifyWg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("NOTIFY: panic (recovered): %v", r)
			}
		}()

		// Limit concurrency to prevent resource exhaustion.
		select {
		case notifySemaphore <- struct{}{}:
			defer func() { <-notifySemaphore }()
		default:
			notificationsTotal.WithLabelValues("skipped").Inc()
			log.Printf("NOTIFY: skipped for user %q on host %q — too many concurrent notifications", username, hostname)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
		defer cancel()

		// Note: exec.CommandContext kills the direct child on timeout but not
		// grandchildren. Avoid notify commands that fork background processes.
		cmd := exec.CommandContext(ctx, "sh", "-c", notifyCmd)

		// Look up per-user notification URLs. Inline map (from NOTIFY_USERS env)
		// takes precedence over the file; file is re-read on each notification
		// so changes take effect without restart.
		var userURLs string
		if notifyUsersInline != nil {
			userURLs = lookupUserURLs(notifyUsersInline, username)
		} else {
			userURLs = lookupUserURLs(loadNotifyUsers(notifyUsersFile), username)
		}

		// Log routing failures for per-user issues (only log when something
		// is wrong to avoid noise on every notification).
		if (notifyUsersFile != "" || notifyUsersInline != nil) && userURLs == "" {
			log.Printf("NOTIFY: no per-user mapping for %q (NOTIFY_USER_URLS will be empty)", username)
		}

		// Minimal environment to avoid leaking server secrets, matching the
		// escrow command pattern. Notification-specific env vars provide all
		// the context the command needs.
		//
		// When a one-tap URL is available it handles both fresh and stale OIDC
		// cases, so use it as the primary approval URL.
		effectiveApprovalURL := approvalURL
		if oneTapURL != "" {
			effectiveApprovalURL = oneTapURL
		}
		cmdEnv := []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + os.Getenv("HOME"),
			"NOTIFY_USERNAME=" + username,
			"NOTIFY_HOSTNAME=" + hostname,
			"NOTIFY_USER_CODE=" + userCode,
			"NOTIFY_APPROVAL_URL=" + effectiveApprovalURL,
			"NOTIFY_EXPIRES_IN=" + fmt.Sprintf("%d", expiresIn),
			"NOTIFY_USER_URLS=" + userURLs,
			"NOTIFY_ONETAP_URL=" + oneTapURL,
		}

		// Pass through configured env var prefixes (e.g., APPRISE_,TELEGRAM_).
		if len(notifyEnv) > 0 {
			for _, env := range os.Environ() {
				// Skip vars already in baseline
				if strings.HasPrefix(env, "PATH=") || strings.HasPrefix(env, "HOME=") || strings.HasPrefix(env, "NOTIFY_") {
					continue
				}
				for _, prefix := range notifyEnv {
					if prefix != "" && strings.HasPrefix(env, prefix) {
						cmdEnv = append(cmdEnv, env)
						break
					}
				}
			}
		}
		cmd.Env = cmdEnv

		// Use separate capped buffers for stdout and stderr to prevent:
		// 1. Memory exhaustion from verbose/malicious commands (limitedWriter cap)
		// 2. Data races from exec.Cmd's internal goroutines writing concurrently
		//    (bytes.Buffer is not goroutine-safe; separate buffers avoid sharing)
		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &limitedWriter{w: &stdoutBuf, n: notifyMaxOutput}
		cmd.Stderr = &limitedWriter{w: &stderrBuf, n: notifyMaxOutput}

		err := cmd.Run()
		if err != nil {
			notificationsTotal.WithLabelValues("failed").Inc()
			combined := truncateOutput(stdoutBuf.String() + stderrBuf.String())
			log.Printf("NOTIFY: command failed for user %q on host %q: %v (output: %s)", username, hostname, err, combined)
			return
		}
		notificationsTotal.WithLabelValues("sent").Inc()
		log.Printf("NOTIFY: sent for user %q on host %q", username, hostname)
	}()
}

// webhookData holds all the fields available to webhook formatters.
type webhookData struct {
	Username    string
	Hostname    string
	UserCode    string
	ApprovalURL string
	OneTapURL   string
	ExpiresIn   int
	Timestamp   string
}

// BestApprovalURL returns the one-tap URL if available, otherwise the dashboard URL.
func (d webhookData) BestApprovalURL() string {
	if d.OneTapURL != "" {
		return d.OneTapURL
	}
	return d.ApprovalURL
}

// formatWebhookRaw returns a generic JSON payload with all challenge fields.
func formatWebhookRaw(d webhookData) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"event":        "challenge_created",
		"username":     d.Username,
		"hostname":     d.Hostname,
		"user_code":    d.UserCode,
		"approval_url": d.ApprovalURL,
		"onetap_url":   d.OneTapURL,
		"expires_in":   d.ExpiresIn,
		"timestamp":    d.Timestamp,
	})
}

// formatWebhookApprise returns a payload suitable for an Apprise API endpoint.
func formatWebhookApprise(d webhookData) ([]byte, error) {
	body := fmt.Sprintf("**User:** %s\n**Host:** %s\n**Code:** `%s`\n**Expires:** %ds\n\n[Approve](%s)",
		d.Username, d.Hostname, d.UserCode, d.ExpiresIn, d.BestApprovalURL())
	return json.Marshal(map[string]interface{}{
		"title":  "Sudo approval needed",
		"body":   body,
		"format": "markdown",
	})
}

// formatWebhookDiscord returns a Discord webhook embed payload.
func formatWebhookDiscord(d webhookData) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"embeds": []map[string]interface{}{{
			"title": "Sudo approval needed",
			"color": 3447003, // blue
			"fields": []map[string]interface{}{
				{"name": "User", "value": d.Username, "inline": true},
				{"name": "Host", "value": d.Hostname, "inline": true},
				{"name": "Code", "value": "`" + d.UserCode + "`", "inline": false},
				{"name": "Expires", "value": fmt.Sprintf("%ds", d.ExpiresIn), "inline": true},
			},
			"url": d.BestApprovalURL(),
		}},
	})
}

// formatWebhookSlack returns a Slack incoming-webhook payload.
func formatWebhookSlack(d webhookData) ([]byte, error) {
	text := fmt.Sprintf("*Sudo approval needed*\nUser: %s | Host: %s | Code: `%s` | Expires: %ds\n<%s|Approve>",
		d.Username, d.Hostname, d.UserCode, d.ExpiresIn, d.BestApprovalURL())
	return json.Marshal(map[string]string{"text": text})
}

// formatWebhookNtfy returns a payload for an ntfy.sh server.
// The topic is read from the URL path (e.g., https://ntfy.sh/mytopic), not the body.
func formatWebhookNtfy(d webhookData) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"title":   "Sudo approval needed",
		"message": fmt.Sprintf("User: %s\nHost: %s\nCode: %s\nExpires: %ds", d.Username, d.Hostname, d.UserCode, d.ExpiresIn),
		"actions": []map[string]string{
			{"action": "view", "label": "Approve", "url": d.BestApprovalURL()},
		},
	})
}

// formatWebhookCustom renders tmpl as a Go text/template with d as data and
// returns the result as the raw HTTP body (must be valid JSON for most receivers).
func formatWebhookCustom(d webhookData, tmpl string) ([]byte, error) {
	t, err := template.New("webhook").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// webhookClient is a hardened HTTP client for webhook delivery:
// no proxy (prevents SSRF via proxy env vars) and no redirect following
// (prevents redirect-based SSRF to internal hosts).
var webhookClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{Proxy: nil},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// sendWebhookNotifications fires each configured webhook in its own goroutine.
// It is a no-op when no webhooks are configured.
func (s *Server) sendWebhookNotifications(d webhookData) {
	for _, wh := range s.cfg.Webhooks {
		s.notifyWg.Add(1)
		go func(wh WebhookConfig) {
			defer s.notifyWg.Done()
			s.fireWebhook(wh, d)
		}(wh)
	}
}

// fireWebhook formats and delivers a single webhook. Errors are logged but
// never returned — callers should not depend on delivery success.
func (s *Server) fireWebhook(wh WebhookConfig, d webhookData) {
	var (
		body []byte
		err  error
	)

	switch wh.Format {
	case "apprise":
		body, err = formatWebhookApprise(d)
	case "discord":
		body, err = formatWebhookDiscord(d)
	case "slack":
		body, err = formatWebhookSlack(d)
	case "ntfy":
		body, err = formatWebhookNtfy(d)
	case "custom":
		body, err = formatWebhookCustom(d, wh.Template)
	default: // "raw" or unrecognised — fall back to raw
		body, err = formatWebhookRaw(d)
	}

	if err != nil {
		log.Printf("ERROR: formatting webhook (format=%q): %v", wh.Format, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		log.Printf("ERROR: creating webhook request (format=%q): %v", wh.Format, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}

	resp, err := webhookClient.Do(req)
	if err != nil {
		log.Printf("ERROR: webhook (format=%q) delivery failed: %v", wh.Format, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("ERROR: webhook (format=%q) returned %d: %s", wh.Format, resp.StatusCode, string(respBody))
	}
}

// WaitForNotifications blocks until all in-flight notification goroutines
// complete or the timeout expires.
func (s *Server) WaitForNotifications(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.notifyWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Printf("NOTIFY: timed out waiting for %s — some notifications may not have completed", timeout)
	}
}
