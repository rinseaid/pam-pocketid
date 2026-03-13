package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
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

	// Set after OIDC callback confirms identity
	ApprovedBy string    `json:"-"`
	ApprovedAt time.Time `json:"-"`
}

// ChallengeStore manages in-memory sudo challenges with TTL expiration.
type ChallengeStore struct {
	mu          sync.RWMutex
	challenges  map[string]*Challenge // keyed by ID
	byCode      map[string]string     // user_code -> ID
	pendingByUser map[string]int      // username -> count of pending non-expired challenges
	ttl         time.Duration
	stopCh      chan struct{} // signals reapLoop to stop
	stopOnce    sync.Once    // ensures Stop is safe to call concurrently
}

// NewChallengeStore creates a new store with the given challenge TTL.
func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	s := &ChallengeStore{
		challenges:    make(map[string]*Challenge),
		byCode:        make(map[string]string),
		pendingByUser: make(map[string]int),
		ttl:           ttl,
		stopCh:        make(chan struct{}),
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

// Create generates a new challenge for the given username and optional hostname.
func (s *ChallengeStore) Create(username, hostname string) (*Challenge, error) {
	id, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generating challenge ID: %w", err)
	}

	code, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}

	now := time.Now()
	c := &Challenge{
		ID:        id,
		UserCode:  code,
		Username:  username,
		Hostname:  hostname,
		Status:    StatusPending,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Rate limit: cap total challenges to prevent memory exhaustion DoS
	if len(s.challenges) >= maxTotalChallenges {
		return nil, fmt.Errorf("too many active challenges, try again later")
	}

	// Rate limit: cap per-user pending challenges (O(1) via counter map)
	if s.pendingByUser[username] >= maxChallengesPerUser {
		return nil, fmt.Errorf("too many pending challenges for user %q, wait for existing ones to expire", username)
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
	s.decPending(c.Username)
	return nil
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
