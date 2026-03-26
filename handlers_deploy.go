package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// deployTimeout is the maximum time a single deploy operation may run.
const deployTimeout = 3 * time.Minute

// deployMaxOutput caps the number of bytes stored per job to prevent OOM.
const deployMaxOutput = 1 << 20 // 1 MB

// deployMaxConcurrent limits simultaneous SSH deploy operations.
const deployMaxConcurrent = 3

// deployIPCooldown is the minimum interval between deploys from the same IP.
const deployIPCooldown = 15 * time.Second

// deployRequestMaxBody caps the deploy request body (private keys can be large).
const deployRequestMaxBody = 65536 // 64 KB

// deploySemaphore limits concurrent deploy operations server-wide.
var deploySemaphore = make(chan struct{}, deployMaxConcurrent)

// deployJob tracks a running or completed remote-install job.
type deployJob struct {
	id        string
	host      string
	sshUser   string
	createdAt time.Time

	mu     sync.Mutex
	buf    bytes.Buffer
	done   bool
	failed bool
	notify chan struct{} // closed when new output is available; replaced each time
}

func newDeployJob(id, host, sshUser string) *deployJob {
	return &deployJob{
		id:        id,
		host:      host,
		sshUser:   sshUser,
		createdAt: time.Now(),
		notify:    make(chan struct{}),
	}
}

// appendOutput appends p to the job's buffer and wakes SSE listeners.
// Silently truncates once deployMaxOutput is reached.
func (j *deployJob) appendOutput(p []byte) {
	j.mu.Lock()
	defer j.mu.Unlock()
	avail := deployMaxOutput - j.buf.Len()
	if avail > 0 {
		if len(p) > avail {
			p = p[:avail]
		}
		j.buf.Write(p)
	}
	close(j.notify)
	j.notify = make(chan struct{})
}

func (j *deployJob) appendLine(s string) {
	j.appendOutput([]byte(s + "\n"))
}

// finish marks the job done and wakes listeners one last time.
func (j *deployJob) finish(failed bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = true
	j.failed = failed
	close(j.notify)
}

// snapshot returns a copy of current output and status, plus the current
// notification channel (to wait on for the next update).
func (j *deployJob) snapshot() (data []byte, done, failed bool, notify <-chan struct{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	snap := make([]byte, j.buf.Len())
	copy(snap, j.buf.Bytes())
	return snap, j.done, j.failed, j.notify
}

// --- IP rate limiter ---

type deployRateLimiter struct {
	mu      sync.Mutex
	lastSeen map[string]time.Time
}

func newDeployRateLimiter() *deployRateLimiter {
	return &deployRateLimiter{lastSeen: make(map[string]time.Time)}
}

// allow returns true if the given IP is allowed to start a deploy now,
// and records the attempt.
func (r *deployRateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if last, ok := r.lastSeen[ip]; ok && time.Since(last) < deployIPCooldown {
		return false
	}
	r.lastSeen[ip] = time.Now()
	return true
}

// --- Handlers ---

// handleDeployUsers returns PocketID users with at least one sshPublicKey* claim.
// GET /api/deploy/users — admin-only
func (s *Server) handleDeployUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.getSessionUser(r) == "" || s.getSessionRole(r) != "admin" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.pocketIDClient == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	users, err := s.pocketIDClient.UsersWithSSHKeys()
	if err != nil {
		log.Printf("deploy/users: %v", err)
		http.Error(w, "failed to fetch users", http.StatusInternalServerError)
		return
	}
	type userEntry struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	out := make([]userEntry, 0, len(users))
	for _, u := range users {
		out = append(out, userEntry{Username: u.Username, Email: u.Email})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// handleDeploy starts an SSH remote-install job.
// POST /api/deploy — admin-only; caller IP must be in DeployAllowCIDRs.
func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Admin session check
	if s.getSessionUser(r) == "" || s.getSessionRole(r) != "admin" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// CIDR allowlist — if unconfigured, feature is disabled
	if len(s.cfg.DeployAllowCIDRs) == 0 {
		http.Error(w, "auto-deploy not configured (PAM_POCKETID_DEPLOY_ALLOW_CIDR not set)", http.StatusForbidden)
		return
	}
	callerIP := clientIP(r)
	if !cidrContains(s.cfg.DeployAllowCIDRs, callerIP) {
		log.Printf("deploy: rejected request from %s (not in allow-list)", callerIP)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Per-IP rate limit
	if !s.deployRL.allow(callerIP) {
		http.Error(w, "too many requests — wait before retrying", http.StatusTooManyRequests)
		return
	}

	body := io.LimitReader(r.Body, deployRequestMaxBody)
	var req struct {
		Hostname     string `json:"hostname"`
		Port         int    `json:"port"`
		SSHUser      string `json:"ssh_user"`
		PrivateKey   string `json:"private_key"`
		PocketIDUser string `json:"pocketid_user"` // informational only
	}
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Hostname == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}
	if !validHostname.MatchString(req.Hostname) {
		http.Error(w, "invalid hostname", http.StatusBadRequest)
		return
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}
	if !validUsername.MatchString(req.SSHUser) {
		http.Error(w, "invalid ssh_user", http.StatusBadRequest)
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		req.Port = 22
	}
	if req.PrivateKey == "" {
		http.Error(w, "private_key required", http.StatusBadRequest)
		return
	}

	// Parse the private key eagerly to fail fast (key never stored)
	signer, err := gossh.ParsePrivateKey([]byte(req.PrivateKey))
	if err != nil {
		http.Error(w, "invalid private key: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Acquire semaphore (non-blocking)
	select {
	case deploySemaphore <- struct{}{}:
	default:
		http.Error(w, "server busy — too many concurrent deploys", http.StatusServiceUnavailable)
		return
	}

	jobID, err := randomHex(12)
	if err != nil {
		<-deploySemaphore
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	job := newDeployJob(jobID, req.Hostname, req.SSHUser)
	s.deployMu.Lock()
	s.deployJobs[jobID] = job
	s.deployMu.Unlock()

	installCmd := fmt.Sprintf("curl -fsSL %s/install.sh | sudo bash", strings.TrimRight(s.cfg.ExternalURL, "/"))

	go func() {
		defer func() { <-deploySemaphore }()
		runDeployJob(job, req.Hostname, req.Port, req.SSHUser, signer, installCmd)
		// zero the signer (best-effort, GC will handle the rest)
		signer = nil
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": jobID})
}

// handleDeployStream streams deploy job output as SSE.
// GET /api/deploy/stream/{id} — admin-only
func (s *Server) handleDeployStream(w http.ResponseWriter, r *http.Request) {
	if s.getSessionUser(r) == "" || s.getSessionRole(r) != "admin" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract job ID from path: /api/deploy/stream/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/deploy/stream/")
	jobID := strings.TrimSpace(path)
	if jobID == "" || !isHex(jobID) {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return
	}

	s.deployMu.Lock()
	job, ok := s.deployJobs[jobID]
	s.deployMu.Unlock()
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, canFlush := w.(http.Flusher)

	sent := 0 // bytes already sent
	for {
		data, done, failed, notify := job.snapshot()

		// Send any new bytes
		if len(data) > sent {
			newData := data[sent:]
			// Emit line by line as SSE events for clean display
			lines := strings.Split(string(newData), "\n")
			for i, line := range lines {
				if i == len(lines)-1 && line == "" {
					break // trailing newline
				}
				fmt.Fprintf(w, "data: %s\n\n", line)
			}
			sent = len(data)
			if canFlush {
				flusher.Flush()
			}
		}

		if done {
			status := "done"
			if failed {
				status = "failed"
			}
			fmt.Fprintf(w, "event: status\ndata: %s\n\n", status)
			if canFlush {
				flusher.Flush()
			}
			return
		}

		// Wait for new output or client disconnect
		select {
		case <-notify:
			// new data available; loop
		case <-r.Context().Done():
			return
		case <-time.After(30 * time.Second):
			// keepalive comment
			fmt.Fprintf(w, ": keepalive\n\n")
			if canFlush {
				flusher.Flush()
			}
		}
	}
}

// runDeployJob connects via SSH and runs the install command, streaming output to job.
func runDeployJob(job *deployJob, hostname string, port int, sshUser string, signer gossh.Signer, cmd string) {
	addr := fmt.Sprintf("%s:%d", hostname, port)
	job.appendLine(fmt.Sprintf("Connecting to %s as %s …", addr, sshUser))

	cfg := &gossh.ClientConfig{
		User:            sshUser,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint — deploying to new hosts; no known_hosts
		Timeout:         15 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		job.appendLine("ERROR: " + err.Error())
		job.finish(true)
		return
	}
	defer client.Close()
	job.appendLine("Connected. Running install script …")

	sess, err := client.NewSession()
	if err != nil {
		job.appendLine("ERROR: failed to open session: " + err.Error())
		job.finish(true)
		return
	}
	defer sess.Close()

	// Stream stdout and stderr back to the job buffer via a pipe
	pr, pw := io.Pipe()
	sess.Stdout = pw
	sess.Stderr = pw

	if err := sess.Start(cmd); err != nil {
		pw.Close()
		job.appendLine("ERROR: " + err.Error())
		job.finish(true)
		return
	}

	// Read pipe and push to job (bounded by deployTimeout)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				job.appendOutput(buf[:n])
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	// Enforce overall timeout
	timer := time.NewTimer(deployTimeout)
	defer timer.Stop()

	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()

	select {
	case waitErr := <-waitDone:
		pw.Close()
		<-done
		if waitErr != nil {
			job.appendLine("ERROR: " + waitErr.Error())
			job.finish(true)
		} else {
			job.appendLine("Install completed successfully.")
			job.finish(false)
		}
	case <-timer.C:
		sess.Signal(gossh.SIGKILL)
		pw.Close()
		job.appendLine("ERROR: timed out after " + deployTimeout.String())
		job.finish(true)
	}
}

// clientIP extracts the real client IP from the request.
func clientIP(r *http.Request) string {
	// Trust X-Forwarded-For only if behind a known proxy — for now use RemoteAddr.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// cidrContains reports whether ip falls within any of the given CIDRs.
func cidrContains(cidrs []*net.IPNet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
