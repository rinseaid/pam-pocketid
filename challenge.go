package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
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

// ChallengeStore manages in-memory sudo challenges with TTL expiration.
type ChallengeStore struct {
	mu                 sync.RWMutex
	challenges         map[string]*Challenge // keyed by ID
	byCode             map[string]string     // user_code -> ID
	pendingByUser      map[string]int        // username -> count of pending non-expired challenges
	lastApproval       map[string]time.Time  // graceKey -> expiry time (for grace period)
	revokeTokensBefore map[string]time.Time  // username -> revocation timestamp
	ttl                time.Duration
	gracePeriod        time.Duration
	persistPath        string        // file path for persisted state (empty = no persistence)
	stopCh             chan struct{} // signals reapLoop to stop
	stopOnce           sync.Once    // ensures Stop is safe to call concurrently
}

// persistedState is the JSON-serializable snapshot of grace sessions and revocation timestamps.
type persistedState struct {
	GraceSessions      map[string]time.Time `json:"grace_sessions"`
	RevokeTokensBefore map[string]time.Time `json:"revoke_tokens_before"`
}

// NewChallengeStore creates a new store with the given challenge TTL, grace period,
// and optional persistence file path. If persistPath is empty, no state is persisted.
func NewChallengeStore(ttl, gracePeriod time.Duration, persistPath string) *ChallengeStore {
	s := &ChallengeStore{
		challenges:         make(map[string]*Challenge),
		byCode:             make(map[string]string),
		pendingByUser:      make(map[string]int),
		lastApproval:       make(map[string]time.Time),
		revokeTokensBefore: make(map[string]time.Time),
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

	// Snapshot revokeTokensBefore for this challenge
	s.mu.RLock()
	var revokeTokensBefore string
	if t, ok := s.revokeTokensBefore[username]; ok {
		revokeTokensBefore = t.Format(time.RFC3339)
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
			sessions = append(sessions, GraceSession{Hostname: "(unknown)", ExpiresAt: expiry})
		} else if strings.HasPrefix(key, prefix) {
			hostname := key[len(prefix):]
			sessions = append(sessions, GraceSession{Hostname: hostname, ExpiresAt: expiry})
		}
	}
	return sessions
}

// RevokeSession removes a grace session for a user on a specific hostname
// and sets the revocation timestamp so that token caches are invalidated.
func (s *ChallengeStore) RevokeSession(username, hostname string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := graceKey(username, hostname)
	delete(s.lastApproval, key)
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
	if pruned {
		s.saveStateLocked()
	}
}

// loadState reads persisted grace sessions and revocation timestamps from the JSON file.
// Handles missing file (first run) and corrupt JSON gracefully — starts fresh.
func (s *ChallengeStore) loadState() {
	if s.persistPath == "" {
		return
	}
	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("WARNING: cannot read session state file %s: %v — starting fresh", s.persistPath, err)
		}
		return
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
	log.Printf("Loaded %d grace sessions and %d revocation entries from %s", len(s.lastApproval), len(s.revokeTokensBefore), s.persistPath)
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
	}
	for key, expiry := range s.lastApproval {
		if now.Before(expiry) {
			state.GraceSessions[key] = expiry
		}
	}
	for user, ts := range s.revokeTokensBefore {
		state.RevokeTokensBefore[user] = ts
	}
	data, err := json.Marshal(state)
	if err != nil {
		log.Printf("ERROR: marshaling session state: %v", err)
		return
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
