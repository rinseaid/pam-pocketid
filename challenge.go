package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Sentinel errors for rate limiting. Checked via errors.Is in server.go
// instead of fragile string matching.
var (
	ErrTooManyChallenges = errors.New("too many active challenges")
	ErrTooManyPerUser    = errors.New("too many pending challenges for user")
)

// ChallengeStatus represents the state of a sudo challenge.
type ChallengeStatus string

const (
	StatusPending  ChallengeStatus = "pending"
	StatusApproved ChallengeStatus = "approved"
	StatusDenied   ChallengeStatus = "denied"
	StatusExpired  ChallengeStatus = "expired"
)

const (
	// maxChallengesPerUser limits how many pending challenges a single username can have.
	// Prevents memory exhaustion DoS via unlimited challenge creation.
	maxChallengesPerUser = 5

	// maxTotalChallenges is an absolute cap on total challenges in the store.
	maxTotalChallenges = 10000
)

// GraceSession represents an active grace period session for a specific host.
type GraceSession struct {
	Username  string
	Hostname  string
	ExpiresAt time.Time
}

// Challenge represents a sudo elevation request awaiting user approval.
type Challenge struct {
	ID        string          `json:"id"`
	UserCode  string          `json:"user_code"`
	Username  string          `json:"username"`
	Status    ChallengeStatus `json:"status"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`

	// Nonce ties the OIDC state to this challenge, preventing CSRF/replay.
	// The nonce is generated when the user clicks "login" and verified on callback.
	Nonce string `json:"-"`

	// Hostname of the machine requesting sudo (sent by PAM client, optional)
	Hostname string `json:"hostname,omitempty"`

	// BreakglassRotateBefore is the server's rotation signal at challenge creation time.
	// Stored per-challenge so the HMAC is consistent even if the server config changes
	// between challenge creation and poll-time approval.
	BreakglassRotateBefore string `json:"-"`

	// RequestedGrace is the per-challenge grace duration selected by the user
	// on the approval page. Zero means use the server's default grace period.
	RequestedGrace time.Duration `json:"-"`

	// RevokeTokensBefore is the server's revocation signal at challenge creation time.
	// Stored per-challenge so the HMAC is consistent even if revocations happen
	// between challenge creation and poll-time approval.
	RevokeTokensBefore string `json:"-"`

	// Set after OIDC callback confirms identity
	ApprovedBy string    `json:"-"`
	ApprovedAt time.Time `json:"-"`

	// RawIDToken stores the OIDC id_token after approval, for forwarding to
	// the PAM client's token cache. Not serialized to JSON.
	RawIDToken string `json:"-"`
}

// ActionLogEntry records an action taken on the dashboard (approval, revocation, etc.).
type ActionLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`         // "approved", "revoked", "auto_approved"
	Hostname  string    `json:"hostname"`
	Code      string    `json:"code,omitempty"`
	Actor     string    `json:"actor,omitempty"` // who performed the action (empty = self)
}

// maxActionLogPrune is the per-user entry limit applied when the state file
// exceeds 1 MB and gets rotated.  Between rotations the log grows unbounded.
const maxActionLogPrune = 1000

// EscrowRecord stores metadata about a host's escrowed break-glass password.
type EscrowRecord struct {
	Timestamp time.Time `json:"timestamp"`
	ItemID    string    `json:"item_id,omitempty"`   // external secrets manager item ID
	VaultID   string    `json:"vault_id,omitempty"`  // resolved vault/container UUID (1password-connect)
}

// ChallengeStore manages in-memory sudo challenges with TTL expiration.
type ChallengeStore struct {
	mu                 sync.RWMutex
	challenges         map[string]*Challenge // keyed by ID
	byCode             map[string]string     // user_code -> ID
	pendingByUser      map[string]int        // username -> count of pending non-expired challenges
	lastApproval       map[string]time.Time  // graceKey -> expiry time (for grace period)
	revokeTokensBefore     map[string]time.Time  // username -> revocation timestamp
	rotateBreakglassBefore map[string]time.Time  // hostname -> per-host rotate-before timestamp
	actionLog              map[string][]ActionLogEntry // username -> last N action log entries
	escrowedHosts          map[string]EscrowRecord // hostname -> escrow metadata
	oneTapUsed         map[string]bool       // challenge ID -> whether one-tap was consumed
	lastOIDCAuth       map[string]time.Time  // username -> last OIDC authentication time
	ttl                time.Duration
	gracePeriod        time.Duration
	persistPath        string        // file path for persisted state (empty = no persistence)
	stopCh             chan struct{} // signals reapLoop to stop
	stopOnce           sync.Once    // ensures Stop is safe to call concurrently
}

// persistedState is the JSON-serializable snapshot of grace sessions, revocation timestamps,
// action log entries, and escrowed host records.
type persistedState struct {
	GraceSessions          map[string]time.Time        `json:"grace_sessions"`
	RevokeTokensBefore     map[string]time.Time        `json:"revoke_tokens_before"`
	RotateBreakglassBefore map[string]time.Time        `json:"rotate_breakglass_before_hosts,omitempty"`
	ActionLog              map[string][]ActionLogEntry  `json:"action_log,omitempty"`
	EscrowedHosts          map[string]EscrowRecord      `json:"escrowed_hosts,omitempty"`
	LastOIDCAuth           map[string]time.Time         `json:"last_oidc_auth,omitempty"`
}

// NewChallengeStore creates a new store with the given challenge TTL, grace period,
// and optional persistence file path. If persistPath is empty, no state is persisted.
func NewChallengeStore(ttl, gracePeriod time.Duration, persistPath string) *ChallengeStore {
	s := &ChallengeStore{
		challenges:         make(map[string]*Challenge),
		byCode:             make(map[string]string),
		pendingByUser:      make(map[string]int),
		lastApproval:       make(map[string]time.Time),
		revokeTokensBefore:     make(map[string]time.Time),
		rotateBreakglassBefore: make(map[string]time.Time),
		actionLog:              make(map[string][]ActionLogEntry),
		escrowedHosts:      make(map[string]EscrowRecord),
		oneTapUsed:         make(map[string]bool),
		lastOIDCAuth:       make(map[string]time.Time),
		ttl:                ttl,
		gracePeriod:        gracePeriod,
		persistPath:        persistPath,
		stopCh:             make(chan struct{}),
	}
	if persistPath != "" {
		s.loadState()
	}
	go s.reapLoop()
	return s
}

// Stop cleanly shuts down the reap goroutine. Safe to call concurrently.
func (s *ChallengeStore) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

// graceKey returns the key used for per-host grace period tracking.
// Format: "username@hostname" or just "username" if hostname is empty.
func graceKey(username, hostname string) string {
	if hostname == "" {
		return username
	}
	return username + "@" + hostname
}

// Create generates a new challenge for the given username, optional hostname,
// and optional BreakglassRotateBefore snapshot (set before insertion to avoid data races).
func (s *ChallengeStore) Create(username, hostname, breakglassRotateBefore string) (*Challenge, error) {
	id, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generating challenge ID: %w", err)
	}

	code, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}

	now := time.Now()

	// Snapshot revokeTokensBefore and per-host rotate-before for this challenge
	s.mu.RLock()
	var revokeTokensBefore string
	if t, ok := s.revokeTokensBefore[username]; ok {
		revokeTokensBefore = t.Format(time.RFC3339)
	}
	// Check per-host rotate-before; use it if it's newer than the global one
	if hostname != "" {
		if perHostT, ok := s.rotateBreakglassBefore[hostname]; ok {
			globalT, _ := time.Parse(time.RFC3339, breakglassRotateBefore)
			if perHostT.After(globalT) {
				breakglassRotateBefore = perHostT.Format(time.RFC3339)
			}
		}
	}
	s.mu.RUnlock()

	c := &Challenge{
		ID:                     id,
		UserCode:               code,
		Username:               username,
		Hostname:               hostname,
		BreakglassRotateBefore: breakglassRotateBefore,
		RevokeTokensBefore:     revokeTokensBefore,
		Status:                 StatusPending,
		CreatedAt:              now,
		ExpiresAt:              now.Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Rate limit: cap total challenges to prevent memory exhaustion DoS
	if len(s.challenges) >= maxTotalChallenges {
		return nil, fmt.Errorf("try again later: %w", ErrTooManyChallenges)
	}

	// Rate limit: cap per-user pending challenges (O(1) via counter map)
	if s.pendingByUser[username] >= maxChallengesPerUser {
		return nil, fmt.Errorf("user %q, wait for existing ones to expire: %w", username, ErrTooManyPerUser)
	}

	// Ensure no user code collision (astronomically unlikely, but defense in depth)
	if _, exists := s.byCode[code]; exists {
		return nil, fmt.Errorf("user code collision, try again")
	}

	s.challenges[id] = c
	s.byCode[code] = id
	s.pendingByUser[username]++
	return c, nil
}

// Get retrieves a challenge by ID. Returns a snapshot copy to avoid data races
// when callers read fields after the lock is released.
func (s *ChallengeStore) Get(id string) (Challenge, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.challenges[id]
	if !ok {
		return Challenge{}, false
	}
	if time.Now().After(c.ExpiresAt) {
		return Challenge{}, false
	}
	return *c, true
}

// GetByCode retrieves a challenge by user code.
func (s *ChallengeStore) GetByCode(code string) (Challenge, bool) {
	s.mu.RLock()
	id, ok := s.byCode[code]
	s.mu.RUnlock()
	if !ok {
		return Challenge{}, false
	}
	return s.Get(id)
}

// SetNonce stores the OIDC nonce on a challenge when the login flow begins.
// This binds the OIDC authentication to this specific challenge, preventing CSRF.
// Also re-checks status and expiry under the write lock to close the TOCTOU gap
// between GetByCode (which returns a snapshot) and this mutation.
func (s *ChallengeStore) SetNonce(id string, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return fmt.Errorf("challenge expired")
	}
	if c.Status != StatusPending {
		return fmt.Errorf("challenge already resolved")
	}
	if c.Nonce != "" {
		return fmt.Errorf("nonce already set (login already initiated)")
	}
	c.Nonce = nonce
	return nil
}

// SetRequestedGrace sets the per-challenge grace duration selected on the approval page.
func (s *ChallengeStore) SetRequestedGrace(id string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.challenges[id]; ok {
		c.RequestedGrace = d
	}
}

// Approve marks a challenge as approved by the given identity.
func (s *ChallengeStore) Approve(id string, approvedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return fmt.Errorf("challenge expired")
	}
	if c.Status != StatusPending {
		return fmt.Errorf("challenge already resolved")
	}
	c.Status = StatusApproved
	c.ApprovedBy = approvedBy
	c.ApprovedAt = time.Now()
	if s.gracePeriod > 0 {
		key := graceKey(c.Username, c.Hostname)
		graceDur := c.RequestedGrace
		if graceDur == 0 {
			graceDur = s.gracePeriod
		}
		s.lastApproval[key] = time.Now().Add(graceDur)
	}
	graceSessions.Set(float64(len(s.lastApproval)))
	s.decPending(c.Username)
	s.saveStateLocked()
	return nil
}

// SetIDToken stores the raw OIDC id_token on an approved challenge.
// Called after approval so the PAM client can cache the token locally.
func (s *ChallengeStore) SetIDToken(id string, rawIDToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return
	}
	c.RawIDToken = rawIDToken
}

// Deny marks a challenge as denied.
func (s *ChallengeStore) Deny(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return fmt.Errorf("challenge expired")
	}
	if c.Status != StatusPending {
		return fmt.Errorf("challenge already resolved")
	}
	c.Status = StatusDenied
	s.decPending(c.Username)
	return nil
}

// WithinGracePeriod returns true if the user has a recent approval within the grace period
// for the given hostname.
func (s *ChallengeStore) WithinGracePeriod(username, hostname string) bool {
	if s.gracePeriod <= 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := graceKey(username, hostname)
	expiry, ok := s.lastApproval[key]
	if !ok {
		return false
	}
	return time.Now().Before(expiry)
}

// GraceRemaining returns how much of the grace period remains for a user on a host.
func (s *ChallengeStore) GraceRemaining(username, hostname string) time.Duration {
	if s.gracePeriod <= 0 {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := graceKey(username, hostname)
	expiry, ok := s.lastApproval[key]
	if !ok {
		return 0
	}
	remaining := time.Until(expiry)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// PendingChallenges returns all pending, non-expired challenges for a username.
func (s *ChallengeStore) PendingChallenges(username string) []Challenge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var result []Challenge
	for _, c := range s.challenges {
		if c.Username == username && c.Status == StatusPending && now.Before(c.ExpiresAt) {
			result = append(result, *c)
		}
	}
	return result
}

// AutoApprove immediately approves a challenge (used for grace period bypass).
// Does NOT update lastApproval — the existing grace session continues unchanged.
func (s *ChallengeStore) AutoApprove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	if c.Status != StatusPending {
		return fmt.Errorf("challenge already resolved")
	}
	c.Status = StatusApproved
	c.ApprovedBy = c.Username
	c.ApprovedAt = time.Now()
	// AutoApprove does NOT update lastApproval — the existing grace session
	// continues with its original expiry.
	s.decPending(c.Username)
	return nil
}

// ActiveSessions returns all active grace sessions for a given username.
func (s *ChallengeStore) ActiveSessions(username string) []GraceSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prefix := username + "@"
	var sessions []GraceSession
	now := time.Now()
	for key, expiry := range s.lastApproval {
		if !now.Before(expiry) {
			continue // expired
		}
		if key == username {
			// Entry without hostname
			sessions = append(sessions, GraceSession{Username: username, Hostname: "(unknown)", ExpiresAt: expiry})
		} else if strings.HasPrefix(key, prefix) {
			hostname := key[len(prefix):]
			sessions = append(sessions, GraceSession{Username: username, Hostname: hostname, ExpiresAt: expiry})
		}
	}
	return sessions
}

// AllPendingChallenges returns all pending, non-expired challenges across all users.
func (s *ChallengeStore) AllPendingChallenges() []Challenge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var result []Challenge
	for _, c := range s.challenges {
		if c.Status == StatusPending && now.Before(c.ExpiresAt) {
			result = append(result, *c)
		}
	}
	return result
}

// AllActiveSessions returns all active grace sessions across all users.
func (s *ChallengeStore) AllActiveSessions() []GraceSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var sessions []GraceSession
	for key, expiry := range s.lastApproval {
		if !now.Before(expiry) {
			continue
		}
		parts := strings.SplitN(key, "@", 2)
		hostname := "(unknown)"
		username := key
		if len(parts) == 2 {
			username = parts[0]
			hostname = parts[1]
		}
		sessions = append(sessions, GraceSession{
			Username:  username,
			Hostname:  hostname,
			ExpiresAt: expiry,
		})
	}
	return sessions
}

// AllActionHistory returns merged action log across all users, most recent first.
func (s *ChallengeStore) AllActionHistory() []ActionLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all []ActionLogEntry
	for _, entries := range s.actionLog {
		all = append(all, entries...)
	}
	// Sort by timestamp descending
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.After(all[j].Timestamp)
	})
	return all
}

// ActionLogEntryWithUser extends ActionLogEntry with the owning username,
// used for cross-user exports (e.g. API key access).
type ActionLogEntryWithUser struct {
	Username  string    `json:"username"`
	Actor     string    `json:"actor,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Hostname  string    `json:"hostname"`
	Code      string    `json:"code,omitempty"`
}

// AllActionHistoryWithUsers returns merged action log across all users (with
// username included per entry), sorted most recent first.
func (s *ChallengeStore) AllActionHistoryWithUsers() []ActionLogEntryWithUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all []ActionLogEntryWithUser
	for user, entries := range s.actionLog {
		for _, e := range entries {
			all = append(all, ActionLogEntryWithUser{
				Username:  user,
				Actor:     e.Actor,
				Timestamp: e.Timestamp,
				Action:    e.Action,
				Hostname:  e.Hostname,
				Code:      e.Code,
			})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Timestamp.After(all[j].Timestamp) })
	return all
}

// LogAction records an action in the per-user action log.
// The log grows unbounded; pruning happens during file rotation in saveStateLocked
// when the serialized state exceeds 1 MB.
// actor is who performed the action; if empty or equal to username (self-action), Actor is not stored.
func (s *ChallengeStore) LogAction(username, action, hostname, code, actor string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := ActionLogEntry{
		Timestamp: time.Now(),
		Action:    action,
		Hostname:  hostname,
		Code:      code,
	}
	if actor != "" && actor != username {
		entry.Actor = actor
	}
	s.actionLog[username] = append(s.actionLog[username], entry)
	s.saveStateLocked()
}

// ActionHistory returns the action log entries for a user, most recent first.
func (s *ChallengeStore) ActionHistory(username string) []ActionLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	log := s.actionLog[username]
	if len(log) == 0 {
		return nil
	}
	// Return a copy in reverse order (most recent first)
	result := make([]ActionLogEntry, len(log))
	for i, e := range log {
		result[len(log)-1-i] = e
	}
	return result
}

// UsersWithHostActivity returns usernames that have action log entries for the given hostname.
func (s *ChallengeStore) UsersWithHostActivity(hostname string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var users []string
	for user, entries := range s.actionLog {
		for _, e := range entries {
			if e.Hostname == hostname {
				users = append(users, user)
				break
			}
		}
	}
	return users
}

// ActiveSessionsForHost returns all users with active grace sessions on a host.
func (s *ChallengeStore) ActiveSessionsForHost(hostname string) []GraceSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var sessions []GraceSession
	suffix := "@" + hostname
	for key, expiry := range s.lastApproval {
		if !now.Before(expiry) {
			continue
		}
		if strings.HasSuffix(key, suffix) {
			username := strings.TrimSuffix(key, suffix)
			sessions = append(sessions, GraceSession{Username: username, Hostname: hostname, ExpiresAt: expiry})
		} else if hostname == "" && !strings.Contains(key, "@") {
			sessions = append(sessions, GraceSession{Username: key, Hostname: "", ExpiresAt: expiry})
		}
	}
	return sessions
}

// KnownHosts returns unique hostnames from the action log for a given user, sorted alphabetically.
func (s *ChallengeStore) KnownHosts(username string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]bool)
	for _, entry := range s.actionLog[username] {
		if entry.Hostname != "" && entry.Hostname != "(unknown)" {
			seen[entry.Hostname] = true
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// CreateGraceSession creates a grace session for a user on a specific hostname with the given duration.
// Used for manual elevation from the hosts page.
func (s *ChallengeStore) CreateGraceSession(username, hostname string, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := graceKey(username, hostname)
	s.lastApproval[key] = time.Now().Add(duration)
	graceSessions.Set(float64(len(s.lastApproval)))
	s.saveStateLocked()
}

// RecordEscrow records that a host has escrowed a break-glass password.
func (s *ChallengeStore) RecordEscrow(hostname, itemID, vaultID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.escrowedHosts[hostname] = EscrowRecord{Timestamp: time.Now(), ItemID: itemID, VaultID: vaultID}
	s.saveStateLocked()
}

// EscrowedHosts returns all hosts with escrowed passwords and their escrow records.
func (s *ChallengeStore) EscrowedHosts() map[string]EscrowRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]EscrowRecord, len(s.escrowedHosts))
	for h, r := range s.escrowedHosts {
		result[h] = r
	}
	return result
}

// SetHostRotateBefore sets the per-host rotate-before timestamp to now and saves state.
func (s *ChallengeStore) SetHostRotateBefore(hostname string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateBreakglassBefore[hostname] = time.Now()
	s.saveStateLocked()
}

// HostRotateBefore returns the per-host rotate-before time, or zero if not set.
func (s *ChallengeStore) HostRotateBefore(hostname string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rotateBreakglassBefore[hostname]
}

// SetAllHostsRotateBefore sets the rotate-before timestamp to now for all given hostnames.
func (s *ChallengeStore) SetAllHostsRotateBefore(hostnames []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, h := range hostnames {
		s.rotateBreakglassBefore[h] = now
	}
	s.saveStateLocked()
}

// ExtendGraceSession extends a grace session to the maximum allowed duration.
// Returns the new remaining duration, or 0 if no session exists.
// Extension is skipped if more than 75% of the grace period remains, preventing
// repeated extension abuse (e.g. clicking extend every day to extend indefinitely).
func (s *ChallengeStore) ExtendGraceSession(username, hostname string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := graceKey(username, hostname)
	expiry, ok := s.lastApproval[key]
	if !ok {
		return 0
	}
	remaining := time.Until(expiry)
	// Don't extend if more than 75% of grace period remains
	if remaining > s.gracePeriod*3/4 {
		return remaining
	}
	newExpiry := time.Now().Add(s.gracePeriod)
	s.lastApproval[key] = newExpiry
	graceSessions.Set(float64(len(s.lastApproval)))
	s.saveStateLocked()
	return s.gracePeriod
}

// ForceExtendGraceSession extends a grace session to the full grace period
// unconditionally, bypassing the 75% guard. Used for admin-initiated extends.
func (s *ChallengeStore) ForceExtendGraceSession(username, hostname string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gracePeriod <= 0 {
		return 0 // grace period disabled; extending would set expiry to "now"
	}
	key := graceKey(username, hostname)
	if _, ok := s.lastApproval[key]; !ok {
		return 0
	}
	newExpiry := time.Now().Add(s.gracePeriod)
	s.lastApproval[key] = newExpiry
	graceSessions.Set(float64(len(s.lastApproval)))
	s.saveStateLocked()
	return s.gracePeriod
}

// RevokeSession removes a grace session for a user on a specific hostname
// and sets the revocation timestamp so that token caches are invalidated.
func (s *ChallengeStore) RevokeSession(username, hostname string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := graceKey(username, hostname)
	delete(s.lastApproval, key)
	graceSessions.Set(float64(len(s.lastApproval)))
	s.revokeTokensBefore[username] = time.Now()
	s.saveStateLocked()
}

// RevokeTokensBefore returns the revocation timestamp for a user, if any.
func (s *ChallengeStore) RevokeTokensBefore(username string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revokeTokensBefore[username]
}

// decPending decrements the pending counter for a username. Must be called under write lock.
func (s *ChallengeStore) decPending(username string) {
	if s.pendingByUser[username] > 0 {
		s.pendingByUser[username]--
	}
	if s.pendingByUser[username] == 0 {
		delete(s.pendingByUser, username)
	}
}

// ConsumeOneTap marks a challenge's one-tap token as used. Returns error if already consumed.
func (s *ChallengeStore) ConsumeOneTap(challengeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oneTapUsed[challengeID] {
		return fmt.Errorf("one-tap already used")
	}
	s.oneTapUsed[challengeID] = true
	return nil
}

// RecordOIDCAuth records the current time as the last OIDC authentication time for the user.
func (s *ChallengeStore) RecordOIDCAuth(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastOIDCAuth[username] = time.Now()
}

// LastOIDCAuth returns the last OIDC authentication time for the user, or zero if never recorded.
func (s *ChallengeStore) LastOIDCAuth(username string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastOIDCAuth[username]
}

// AllUsers returns all usernames that have any data in the store.
func (s *ChallengeStore) AllUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make(map[string]bool)
	for user := range s.actionLog {
		users[user] = true
	}
	for key := range s.lastApproval {
		parts := strings.SplitN(key, "@", 2)
		users[parts[0]] = true
	}
	result := make([]string, 0, len(users))
	for u := range users {
		result = append(result, u)
	}
	sort.Strings(result)
	return result
}

// RemoveUser removes all data for a user: grace sessions, action log, revocation timestamps,
// and any pending challenges (cancelling them to free pending counters and byCode entries).
func (s *ChallengeStore) RemoveUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Cancel pending challenges and clean up all challenge data for this user
	for id, c := range s.challenges {
		if c.Username == username {
			if c.Status == StatusPending {
				s.decPending(username)
			}
			delete(s.byCode, c.UserCode)
			delete(s.challenges, id)
			delete(s.oneTapUsed, id)
		}
	}
	delete(s.pendingByUser, username)
	// Revoke all grace sessions for this user
	prefix := username + "@"
	for key := range s.lastApproval {
		if key == username || strings.HasPrefix(key, prefix) {
			delete(s.lastApproval, key)
		}
	}
	// Set revocation timestamp so token caches are invalidated
	s.revokeTokensBefore[username] = time.Now()
	// Clear action log
	delete(s.actionLog, username)
	// Clear OIDC auth record
	delete(s.lastOIDCAuth, username)
	graceSessions.Set(float64(len(s.lastApproval)))
	s.saveStateLocked()
}

// reapLoop removes expired challenges periodically.
func (s *ChallengeStore) reapLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: panic in challenge reaper (recovered): %v", r)
			// Restart the reaper after a brief delay
			time.Sleep(5 * time.Second)
			go s.reapLoop()
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reap()
		case <-s.stopCh:
			return
		}
	}
}

func (s *ChallengeStore) reap() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.challenges {
		if now.After(c.ExpiresAt.Add(30 * time.Second)) {
			// If the challenge was still pending when reaped, decrement the counter
			if c.Status == StatusPending {
				s.decPending(c.Username)
				challengesExpired.Inc()
				activeChallenges.Dec()
			}
			delete(s.byCode, c.UserCode)
			delete(s.challenges, id)
			delete(s.oneTapUsed, id)
		}
	}
	// Prune stale grace period entries where expiry has passed.
	pruned := false
	for key, expiry := range s.lastApproval {
		if now.After(expiry) {
			delete(s.lastApproval, key)
			pruned = true
		}
	}
	// Prune stale revocation timestamps (older than 30 days)
	cutoff := now.Add(-30 * 24 * time.Hour)
	for user, ts := range s.revokeTokensBefore {
		if ts.Before(cutoff) {
			delete(s.revokeTokensBefore, user)
			pruned = true
		}
	}
	// Prune stale rotate-before timestamps (older than 30 days)
	for host, ts := range s.rotateBreakglassBefore {
		if ts.Before(cutoff) {
			delete(s.rotateBreakglassBefore, host)
			pruned = true
		}
	}
	// Prune stale escrow records (older than configured rotation period + 30 day buffer)
	escrowCutoff := now.Add(-120 * 24 * time.Hour) // 120 days (covers 90-day rotation + buffer)
	for host, record := range s.escrowedHosts {
		if record.Timestamp.Before(escrowCutoff) {
			delete(s.escrowedHosts, host)
			pruned = true
		}
	}
	// Prune stale OIDC auth timestamps (older than 30 days)
	for user, ts := range s.lastOIDCAuth {
		if ts.Before(cutoff) {
			delete(s.lastOIDCAuth, user)
			pruned = true
		}
	}
	if pruned {
		s.saveStateLocked()
	}
	graceSessions.Set(float64(len(s.lastApproval)))
}

// loadState reads persisted grace sessions and revocation timestamps from the JSON file.
// Handles missing file (first run) and corrupt JSON gracefully — starts fresh.
func (s *ChallengeStore) loadState() {
	if s.persistPath == "" {
		return
	}
	f, err := os.OpenFile(s.persistPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("WARNING: cannot open session state file %s: %v — starting fresh", s.persistPath, err)
		}
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		log.Printf("WARNING: cannot stat session state file: %v — starting fresh", err)
		return
	}
	if !info.Mode().IsRegular() {
		log.Printf("WARNING: session state file is not a regular file — starting fresh")
		return
	}
	if info.Mode().Perm()&0077 != 0 {
		log.Printf("WARNING: session state file has insecure permissions %o — starting fresh", info.Mode().Perm())
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, 10<<20)) // 10MB limit
	if err != nil {
		log.Printf("WARNING: cannot read session state file: %v — starting fresh", err)
		return
	}
	// First pass: try to migrate old escrowed_hosts format (map[string]time.Time)
	// before the main unmarshal, which would fail on type mismatch.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		if eh, ok := raw["escrowed_hosts"]; ok {
			var oldFormat map[string]time.Time
			if json.Unmarshal(eh, &oldFormat) == nil && len(oldFormat) > 0 {
				// Old format detected — convert in-place to new format
				newFormat := make(map[string]EscrowRecord, len(oldFormat))
				for host, ts := range oldFormat {
					newFormat[host] = EscrowRecord{Timestamp: ts}
				}
				if converted, err := json.Marshal(newFormat); err == nil {
					raw["escrowed_hosts"] = converted
					if migrated, merr := json.Marshal(raw); merr == nil {
						data = migrated
						log.Printf("Migrated %d escrowed_hosts entries to new format", len(oldFormat))
					}
				}
			}
		}
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("WARNING: corrupt session state file %s: %v — starting fresh", s.persistPath, err)
		return
	}
	now := time.Now()
	for key, expiry := range state.GraceSessions {
		if now.Before(expiry) {
			s.lastApproval[key] = expiry
		}
	}
	for user, ts := range state.RevokeTokensBefore {
		s.revokeTokensBefore[user] = ts
	}
	for user, entries := range state.ActionLog {
		s.actionLog[user] = entries
	}
	for host, rec := range state.EscrowedHosts {
		s.escrowedHosts[host] = rec
	}
	for host, ts := range state.RotateBreakglassBefore {
		s.rotateBreakglassBefore[host] = ts
	}
	for user, ts := range state.LastOIDCAuth {
		s.lastOIDCAuth[user] = ts
	}
	log.Printf("Loaded %d grace sessions, %d revocation entries, %d escrowed hosts from %s", len(s.lastApproval), len(s.revokeTokensBefore), len(s.escrowedHosts), s.persistPath)
	graceSessions.Set(float64(len(s.lastApproval)))
}

// saveStateLocked writes the current grace sessions and revocation timestamps to the
// persist file using atomic temp+rename. Must be called while holding the write lock
// (or from a context where the data is consistent). No-op if persistPath is empty.
func (s *ChallengeStore) saveStateLocked() {
	if s.persistPath == "" {
		return
	}
	// Build state from current in-memory maps, pruning expired entries.
	now := time.Now()
	state := persistedState{
		GraceSessions:      make(map[string]time.Time),
		RevokeTokensBefore: make(map[string]time.Time),
		ActionLog:          make(map[string][]ActionLogEntry),
	}
	for key, expiry := range s.lastApproval {
		if now.Before(expiry) {
			state.GraceSessions[key] = expiry
		}
	}
	for user, ts := range s.revokeTokensBefore {
		state.RevokeTokensBefore[user] = ts
	}
	for user, entries := range s.actionLog {
		if len(entries) > 0 {
			state.ActionLog[user] = entries
		}
	}
	if len(s.escrowedHosts) > 0 {
		state.EscrowedHosts = make(map[string]EscrowRecord, len(s.escrowedHosts))
		for host, rec := range s.escrowedHosts {
			state.EscrowedHosts[host] = rec
		}
	}
	if len(s.rotateBreakglassBefore) > 0 {
		state.RotateBreakglassBefore = make(map[string]time.Time, len(s.rotateBreakglassBefore))
		for host, ts := range s.rotateBreakglassBefore {
			state.RotateBreakglassBefore[host] = ts
		}
	}
	if len(s.lastOIDCAuth) > 0 {
		state.LastOIDCAuth = make(map[string]time.Time, len(s.lastOIDCAuth))
		for user, ts := range s.lastOIDCAuth {
			state.LastOIDCAuth[user] = ts
		}
	}
	data, err := json.Marshal(state)
	if err != nil {
		log.Printf("ERROR: marshaling session state: %v", err)
		return
	}

	// If the serialized state exceeds 1 MB, rotate archive files and prune
	// in-memory action logs so the fresh file starts small.
	if len(data) > 1_000_000 {
		s.rotateStateFiles()
		for user, entries := range s.actionLog {
			if len(entries) > maxActionLogPrune {
				s.actionLog[user] = entries[len(entries)-maxActionLogPrune:]
			}
		}
		// Rebuild state with pruned logs and re-marshal.
		state.ActionLog = make(map[string][]ActionLogEntry)
		for user, entries := range s.actionLog {
			if len(entries) > 0 {
				state.ActionLog[user] = entries
			}
		}
		data, err = json.Marshal(state)
		if err != nil {
			// Rotation already happened but re-marshal failed.
			// Restore the live file from the .1 archive to prevent data loss.
			os.Rename(s.persistPath+".1", s.persistPath)
			log.Printf("ERROR: re-marshaling session state after prune: %v (restored from archive)", err)
			return
		}
	}

	// Atomic write: temp file + rename (same pattern as writeBreakglassFile).
	dir := s.persistPath[:strings.LastIndex(s.persistPath, "/")+1]
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".sessions-tmp-*")
	if err != nil {
		log.Printf("ERROR: creating temp session state file: %v", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		log.Printf("ERROR: writing session state: %v", err)
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		log.Printf("ERROR: syncing session state: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		log.Printf("ERROR: closing session state temp file: %v", err)
		return
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		log.Printf("ERROR: setting session state permissions: %v", err)
		return
	}
	if err := os.Rename(tmpName, s.persistPath); err != nil {
		os.Remove(tmpName)
		log.Printf("ERROR: renaming session state file: %v", err)
		return
	}
}

// rotateStateFiles shifts existing archive files to make room for a new backup.
// sessions.json.8 → sessions.json.9, sessions.json.7 → sessions.json.8, ...,
// sessions.json → sessions.json.1.  Maximum 9 numbered archives (.1 through .9).
func (s *ChallengeStore) rotateStateFiles() {
	for i := 8; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", s.persistPath, i)
		dst := fmt.Sprintf("%s.%d", s.persistPath, i+1)
		// Best-effort: ignore errors (file may not exist yet).
		os.Rename(src, dst)
	}
	// Copy current file to .1 (rename would leave us without the original during write).
	os.Rename(s.persistPath, s.persistPath+".1")
}

// SaveState persists the current grace sessions and revocation timestamps.
// Intended for graceful shutdown — acquires the lock before saving.
func (s *ChallengeStore) SaveState() {
	if s.persistPath == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveStateLocked()
}

// generateUserCode creates a human-friendly code like "ABCDEF-123456".
// Uses 6 letters (24^6 = ~191M) + 6 digits (10^6 = 1M) = ~191 billion combinations.
// This makes brute-force enumeration of active codes infeasible within the TTL window.
func generateUserCode() (string, error) {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I, O (ambiguous)
	const digits = "0123456789"

	code := make([]byte, 13) // XXXXXX-YYYYYY
	for i := 0; i < 6; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		code[i] = letters[n.Int64()]
	}
	code[6] = '-'
	for i := 7; i < 13; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[n.Int64()]
	}
	return string(code), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
