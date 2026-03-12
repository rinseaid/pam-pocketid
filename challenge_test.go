package main

import (
	"fmt"
	"testing"
	"time"
)

func TestChallengeCreate(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	c, err := store.Create("jordan", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.Username != "jordan" {
		t.Errorf("username = %q, want %q", c.Username, "jordan")
	}
	if c.Status != StatusPending {
		t.Errorf("status = %q, want %q", c.Status, StatusPending)
	}
	if c.ID == "" {
		t.Error("ID is empty")
	}
	if c.UserCode == "" {
		t.Error("UserCode is empty")
	}
	if len(c.UserCode) != 13 { // XXXXXX-YYYYYY
		t.Errorf("UserCode length = %d, want 13", len(c.UserCode))
	}
	if c.UserCode[6] != '-' {
		t.Errorf("UserCode[6] = %c, want '-'", c.UserCode[6])
	}
}

func TestChallengeGetByID(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	c, _ := store.Create("alice", "")
	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get returned false")
	}
	if got.Username != "alice" {
		t.Errorf("username = %q, want %q", got.Username, "alice")
	}
}

func TestChallengeGetByCode(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	c, _ := store.Create("bob", "")
	got, ok := store.GetByCode(c.UserCode)
	if !ok {
		t.Fatal("GetByCode returned false")
	}
	if got.ID != c.ID {
		t.Errorf("ID = %q, want %q", got.ID, c.ID)
	}
}

func TestChallengeApprove(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	c, _ := store.Create("jordan", "")
	if err := store.Approve(c.ID, "jordan"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get returned false after approve")
	}
	if got.Status != StatusApproved {
		t.Errorf("status = %q, want %q", got.Status, StatusApproved)
	}
	if got.ApprovedBy != "jordan" {
		t.Errorf("ApprovedBy = %q, want %q", got.ApprovedBy, "jordan")
	}
}

func TestChallengeDeny(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	c, _ := store.Create("jordan", "")
	if err := store.Deny(c.ID); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get returned false after deny")
	}
	if got.Status != StatusDenied {
		t.Errorf("status = %q, want %q", got.Status, StatusDenied)
	}
}

func TestChallengeExpiry(t *testing.T) {
	store := NewChallengeStore(1 * time.Millisecond)
	defer store.Stop()

	c, _ := store.Create("jordan", "")
	time.Sleep(10 * time.Millisecond)

	_, ok := store.Get(c.ID)
	if ok {
		t.Error("Get returned true for expired challenge")
	}
}

func TestChallengeDoubleApprove(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	c, _ := store.Create("jordan", "")
	store.Approve(c.ID, "jordan")

	err := store.Approve(c.ID, "jordan")
	if err == nil {
		t.Error("expected error on double approve")
	}
}

func TestChallengeApproveExpired(t *testing.T) {
	store := NewChallengeStore(1 * time.Millisecond)
	defer store.Stop()

	c, _ := store.Create("jordan", "")
	time.Sleep(10 * time.Millisecond)

	err := store.Approve(c.ID, "jordan")
	if err == nil {
		t.Error("expected error approving expired challenge")
	}
}

func TestChallengeNotFound(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	_, ok := store.Get("nonexistent")
	if ok {
		t.Error("Get returned true for nonexistent challenge")
	}

	err := store.Approve("nonexistent", "jordan")
	if err == nil {
		t.Error("expected error approving nonexistent challenge")
	}
}

func TestUserCodeFormat(t *testing.T) {
	// Generate many codes and check format (XXXXXX-YYYYYY)
	for i := 0; i < 100; i++ {
		code, err := generateUserCode()
		if err != nil {
			t.Fatalf("generateUserCode: %v", err)
		}
		if len(code) != 13 {
			t.Errorf("code length = %d, want 13", len(code))
		}
		// First 6 should be uppercase letters (no I, O)
		for j := 0; j < 6; j++ {
			c := code[j]
			if c < 'A' || c > 'Z' || c == 'I' || c == 'O' {
				t.Errorf("code[%d] = %c, want uppercase letter (not I/O)", j, c)
			}
		}
		if code[6] != '-' {
			t.Errorf("code[6] = %c, want '-'", code[6])
		}
		// Last 6 should be digits
		for j := 7; j < 13; j++ {
			if code[j] < '0' || code[j] > '9' {
				t.Errorf("code[%d] = %c, want digit", j, code[j])
			}
		}
	}
}

func TestUniqueIDs(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()
	ids := make(map[string]bool)

	for i := 0; i < 50; i++ {
		c, err := store.Create(fmt.Sprintf("user%d", i), "")
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		if ids[c.ID] {
			t.Errorf("duplicate ID: %s", c.ID)
		}
		ids[c.ID] = true
	}
}

func TestRateLimitPerUser(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	// Create maxChallengesPerUser challenges for one user
	for i := 0; i < maxChallengesPerUser; i++ {
		_, err := store.Create("jordan", "")
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	// Next one should fail
	_, err := store.Create("jordan", "")
	if err == nil {
		t.Error("expected rate limit error")
	}

	// A different user should still work
	_, err = store.Create("alice", "")
	if err != nil {
		t.Fatalf("Create for different user: %v", err)
	}
}

func TestSetNonce(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	c, _ := store.Create("jordan", "")

	// First set should succeed
	if err := store.SetNonce(c.ID, "nonce1"); err != nil {
		t.Fatalf("SetNonce: %v", err)
	}

	// Second set should fail (prevents double-login)
	if err := store.SetNonce(c.ID, "nonce2"); err == nil {
		t.Error("expected error on second SetNonce")
	}

	// Verify nonce was stored
	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get returned false")
	}
	if got.Nonce != "nonce1" {
		t.Errorf("Nonce = %q, want %q", got.Nonce, "nonce1")
	}
}

func TestSetNonceNotFound(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	if err := store.SetNonce("nonexistent", "nonce"); err == nil {
		t.Error("expected error for nonexistent challenge")
	}
}

func TestStoreStop(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	// Should not panic on double stop
	store.Stop()
	store.Stop()
}

func TestDenyExpiredChallenge(t *testing.T) {
	store := NewChallengeStore(1 * time.Millisecond)
	defer store.Stop()

	c, _ := store.Create("jordan", "")
	time.Sleep(10 * time.Millisecond)

	err := store.Deny(c.ID)
	if err == nil {
		t.Error("expected error denying expired challenge")
	}
}

func TestDenyAfterApprove(t *testing.T) {
	store := NewChallengeStore(60 * time.Second)
	defer store.Stop()

	c, _ := store.Create("jordan", "")
	store.Approve(c.ID, "jordan")

	err := store.Deny(c.ID)
	if err == nil {
		t.Error("expected error denying already-approved challenge")
	}
}
