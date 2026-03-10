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

	// Set after OIDC callback confirms identity
	ApprovedBy string    `json:"-"`
	ApprovedAt time.Time `json:"-"`
}

// ChallengeStore manages in-memory sudo challenges with TTL expiration.
type ChallengeStore struct {
	mu         sync.RWMutex
	challenges map[string]*Challenge // keyed by ID
	byCode     map[string]string     // user_code -> ID
	ttl        time.Duration
	stopCh     chan struct{} // signals reapLoop to stop
}

// NewChallengeStore creates a new store with the given challenge TTL.
func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	s := &ChallengeStore{
		challenges: make(map[string]*Challenge),
		byCode:     make(map[string]string),
		ttl:        ttl,
		stopCh:     make(chan struct{}),
	}
	go s.reapLoop()
	return s
}

// Stop cleanly shuts down the reap goroutine.
func (s *ChallengeStore) Stop() {
	select {
	case <-s.stopCh:
		// already stopped
	default:
		close(s.stopCh)
	}
}

// Create generates a new challenge for the given username.
func (s *ChallengeStore) Create(username string) (*Challenge, error) {
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

	// Rate limit: cap per-user pending challenges
	pendingCount := 0
	for _, existing := range s.challenges {
		if existing.Username == username && existing.Status == StatusPending && now.Before(existing.ExpiresAt) {
			pendingCount++
		}
	}
	if pendingCount >= maxChallengesPerUser {
		return nil, fmt.Errorf("too many pending challenges for user %q, wait for existing ones to expire", username)
	}

	// Ensure no user code collision (astronomically unlikely, but defense in depth)
	if _, exists := s.byCode[code]; exists {
		return nil, fmt.Errorf("user code collision, try again")
	}

	s.challenges[id] = c
	s.byCode[code] = id
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
func (s *ChallengeStore) SetNonce(id string, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return fmt.Errorf("challenge not found")
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
	if c.Status != StatusPending {
		return fmt.Errorf("challenge already resolved")
	}
	c.Status = StatusDenied
	return nil
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
