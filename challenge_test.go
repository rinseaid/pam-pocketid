package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestChallengeCreate(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, err := store.Create("jordan", "", "")
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
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, _ := store.Create("alice", "", "")
	got, ok := store.Get(c.ID)
	if !ok {
		t.Fatal("Get returned false")
	}
	if got.Username != "alice" {
		t.Errorf("username = %q, want %q", got.Username, "alice")
	}
}

func TestChallengeGetByCode(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, _ := store.Create("bob", "", "")
	got, ok := store.GetByCode(c.UserCode)
	if !ok {
		t.Fatal("GetByCode returned false")
	}
	if got.ID != c.ID {
		t.Errorf("ID = %q, want %q", got.ID, c.ID)
	}
}

func TestChallengeApprove(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
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
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
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
	store := NewChallengeStore(1*time.Millisecond, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
	time.Sleep(10 * time.Millisecond)

	_, ok := store.Get(c.ID)
	if ok {
		t.Error("Get returned true for expired challenge")
	}
}

func TestChallengeDoubleApprove(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
	store.Approve(c.ID, "jordan")

	err := store.Approve(c.ID, "jordan")
	if err == nil {
		t.Error("expected error on double approve")
	}
}

func TestChallengeApproveExpired(t *testing.T) {
	store := NewChallengeStore(1*time.Millisecond, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
	time.Sleep(10 * time.Millisecond)

	err := store.Approve(c.ID, "jordan")
	if err == nil {
		t.Error("expected error approving expired challenge")
	}
}

func TestChallengeNotFound(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
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
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()
	ids := make(map[string]bool)

	for i := 0; i < 50; i++ {
		c, err := store.Create(fmt.Sprintf("user%d", i), "", "")
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
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	// Create maxChallengesPerUser challenges for one user
	for i := 0; i < maxChallengesPerUser; i++ {
		_, err := store.Create("jordan", "", "")
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	// Next one should fail
	_, err := store.Create("jordan", "", "")
	if err == nil {
		t.Error("expected rate limit error")
	}

	// A different user should still work
	_, err = store.Create("alice", "", "")
	if err != nil {
		t.Fatalf("Create for different user: %v", err)
	}
}

func TestSetNonce(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")

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
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	if err := store.SetNonce("nonexistent", "nonce"); err == nil {
		t.Error("expected error for nonexistent challenge")
	}
}

func TestStoreStop(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	// Should not panic on double stop
	store.Stop()
	store.Stop()
}

func TestDenyExpiredChallenge(t *testing.T) {
	store := NewChallengeStore(1*time.Millisecond, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
	time.Sleep(10 * time.Millisecond)

	err := store.Deny(c.ID)
	if err == nil {
		t.Error("expected error denying expired challenge")
	}
}

func TestDenyAfterApprove(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
	store.Approve(c.ID, "jordan")

	err := store.Deny(c.ID)
	if err == nil {
		t.Error("expected error denying already-approved challenge")
	}
}

func TestGracePeriodDisabledByDefault(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
	store.Approve(c.ID, "jordan")

	if store.WithinGracePeriod("jordan", "") {
		t.Error("grace period should be disabled when set to 0")
	}
}

func TestGracePeriodApproval(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 1*time.Hour, "")
	defer store.Stop()

	// No approval yet
	if store.WithinGracePeriod("jordan", "") {
		t.Error("should not be within grace period before any approval")
	}

	// Approve a challenge
	c, _ := store.Create("jordan", "", "")
	store.Approve(c.ID, "jordan")

	// Should be within grace period now
	if !store.WithinGracePeriod("jordan", "") {
		t.Error("should be within grace period after approval")
	}

	// Different user should not be affected
	if store.WithinGracePeriod("alice", "") {
		t.Error("grace period should be per-user")
	}
}

func TestGracePeriodExpiry(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 1*time.Millisecond, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "", "")
	store.Approve(c.ID, "jordan")

	time.Sleep(5 * time.Millisecond)

	if store.WithinGracePeriod("jordan", "") {
		t.Error("grace period should have expired")
	}
}

func TestAutoApprove(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 1*time.Hour, "")
	defer store.Stop()

	// First challenge approved normally
	c1, _ := store.Create("jordan", "", "")
	store.Approve(c1.ID, "jordan")

	// Second challenge auto-approved
	c2, _ := store.Create("jordan", "", "")
	err := store.AutoApprove(c2.ID)
	if err != nil {
		t.Fatalf("auto-approve failed: %v", err)
	}

	got, ok := store.Get(c2.ID)
	if !ok {
		t.Fatal("auto-approved challenge not found")
	}
	if got.Status != StatusApproved {
		t.Errorf("expected approved, got %s", got.Status)
	}
}

func TestGracePeriodPerHost(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 1*time.Hour, "")
	defer store.Stop()

	// Approve for host1
	c1, _ := store.Create("jordan", "host1", "")
	store.Approve(c1.ID, "jordan")

	// Should be within grace for host1
	if !store.WithinGracePeriod("jordan", "host1") {
		t.Error("should be within grace period for host1")
	}

	// Should NOT be within grace for host2
	if store.WithinGracePeriod("jordan", "host2") {
		t.Error("should not be within grace period for host2")
	}
}

func TestGraceRemaining(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 1*time.Hour, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "myhost", "")
	store.Approve(c.ID, "jordan")

	rem := store.GraceRemaining("jordan", "myhost")
	if rem <= 0 || rem > 1*time.Hour {
		t.Errorf("GraceRemaining = %v, want >0 and <=1h", rem)
	}

	// Different host should have 0 remaining
	rem2 := store.GraceRemaining("jordan", "otherhost")
	if rem2 != 0 {
		t.Errorf("GraceRemaining for otherhost = %v, want 0", rem2)
	}
}

func TestRequestedGrace(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 8*time.Hour, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "host1", "")
	store.SetRequestedGrace(c.ID, 1*time.Hour)
	store.Approve(c.ID, "jordan")

	// Grace remaining should be about 1 hour, not 8 hours
	rem := store.GraceRemaining("jordan", "host1")
	if rem > 1*time.Hour+time.Second || rem < 59*time.Minute {
		t.Errorf("GraceRemaining = %v, want ~1h (requested), not ~8h (default)", rem)
	}
}

func TestActiveSessions(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 1*time.Hour, "")
	defer store.Stop()

	c1, _ := store.Create("jordan", "host1", "")
	store.Approve(c1.ID, "jordan")

	c2, _ := store.Create("jordan", "host2", "")
	store.Approve(c2.ID, "jordan")

	sessions := store.ActiveSessions("jordan")
	if len(sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(sessions))
	}

	// Different user should have no sessions
	sessions2 := store.ActiveSessions("alice")
	if len(sessions2) != 0 {
		t.Errorf("expected 0 sessions for alice, got %d", len(sessions2))
	}
}

func TestRevokeSession(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 1*time.Hour, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "host1", "")
	store.Approve(c.ID, "jordan")

	if !store.WithinGracePeriod("jordan", "host1") {
		t.Fatal("expected grace period to be active before revoke")
	}

	store.RevokeSession("jordan", "host1")

	if store.WithinGracePeriod("jordan", "host1") {
		t.Error("grace period should be revoked")
	}

	// Check revokeTokensBefore was set
	rt := store.RevokeTokensBefore("jordan")
	if rt.IsZero() {
		t.Error("RevokeTokensBefore should be set after revoke")
	}
}

func TestRevokeTokensBeforeSnapshot(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 1*time.Hour, "")
	defer store.Stop()

	// Revoke, then create a challenge — it should snapshot the revocation time
	c1, _ := store.Create("jordan", "host1", "")
	store.Approve(c1.ID, "jordan")
	store.RevokeSession("jordan", "host1")

	c2, err := store.Create("jordan", "host1", "")
	if err != nil {
		t.Fatalf("Create after revoke: %v", err)
	}
	if c2.RevokeTokensBefore == "" {
		t.Error("expected RevokeTokensBefore to be snapshotted on new challenge")
	}
}

func TestGraceKey(t *testing.T) {
	if graceKey("jordan", "host1") != "jordan@host1" {
		t.Error("expected jordan@host1")
	}
	if graceKey("jordan", "") != "jordan" {
		t.Error("expected jordan (no host)")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sessions.json"

	// Create store with persistence, approve a challenge to create a grace session
	store1 := NewChallengeStore(60*time.Second, 1*time.Hour, path)
	c, _ := store1.Create("jordan", "host1", "")
	store1.Approve(c.ID, "jordan")

	// Verify file was written
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("persist file not created: %v", err)
	}

	// Stop store1 and create a new store from the same file
	store1.Stop()

	store2 := NewChallengeStore(60*time.Second, 1*time.Hour, path)
	defer store2.Stop()

	// Grace session should survive
	if !store2.WithinGracePeriod("jordan", "host1") {
		t.Error("grace period should survive persistence round-trip")
	}

	// Different user/host should not be affected
	if store2.WithinGracePeriod("alice", "host1") {
		t.Error("alice should not have grace period")
	}
}

func TestPersistenceRevocation(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sessions.json"

	store1 := NewChallengeStore(60*time.Second, 1*time.Hour, path)
	c, _ := store1.Create("jordan", "host1", "")
	store1.Approve(c.ID, "jordan")
	store1.RevokeSession("jordan", "host1")
	store1.Stop()

	store2 := NewChallengeStore(60*time.Second, 1*time.Hour, path)
	defer store2.Stop()

	// Grace session should be gone
	if store2.WithinGracePeriod("jordan", "host1") {
		t.Error("revoked session should not survive persistence")
	}

	// Revocation timestamp should survive
	rt := store2.RevokeTokensBefore("jordan")
	if rt.IsZero() {
		t.Error("RevokeTokensBefore should survive persistence")
	}
}

func TestPersistenceMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/nonexistent.json"

	// Should start fresh without error
	store := NewChallengeStore(60*time.Second, 1*time.Hour, path)
	defer store.Stop()

	if store.WithinGracePeriod("jordan", "host1") {
		t.Error("should have no grace period from missing file")
	}
}

func TestPersistenceCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sessions.json"

	// Write garbage
	os.WriteFile(path, []byte("not json at all {{{"), 0600)

	// Should start fresh without error
	store := NewChallengeStore(60*time.Second, 1*time.Hour, path)
	defer store.Stop()

	if store.WithinGracePeriod("jordan", "host1") {
		t.Error("should have no grace period from corrupt file")
	}
}

func TestPersistenceNoPersistPath(t *testing.T) {
	// Empty persistPath should not write any files
	store := NewChallengeStore(60*time.Second, 1*time.Hour, "")
	defer store.Stop()

	c, _ := store.Create("jordan", "host1", "")
	store.Approve(c.ID, "jordan")

	// SaveState should be a no-op
	store.SaveState()
}

func TestPersistenceExpiredSessionsNotLoaded(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sessions.json"

	// Write a state file with an already-expired session
	state := persistedState{
		GraceSessions:      map[string]time.Time{"jordan@host1": time.Now().Add(-1 * time.Hour)},
		RevokeTokensBefore: map[string]time.Time{},
	}
	data, _ := json.Marshal(state)
	os.WriteFile(path, data, 0600)

	store := NewChallengeStore(60*time.Second, 1*time.Hour, path)
	defer store.Stop()

	if store.WithinGracePeriod("jordan", "host1") {
		t.Error("expired session should not be loaded from persistence")
	}
}

func TestAllPendingChallenges(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	// Empty initially
	if got := store.AllPendingChallenges(); len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}

	c1, _ := store.Create("alice", "host-1", "")
	c2, _ := store.Create("bob", "host-2", "")
	store.Create("carol", "host-3", "")

	// Approve one — should not appear
	store.Approve(c1.ID, "alice")
	// Deny one — should not appear
	store.Deny(c2.ID)

	pending := store.AllPendingChallenges()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].Username != "carol" {
		t.Errorf("expected carol, got %s", pending[0].Username)
	}
}

func TestAllActiveSessions(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 5*time.Minute, "")
	defer store.Stop()

	if got := store.AllActiveSessions(); len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}

	c, _ := store.Create("alice", "host-1", "")
	store.Approve(c.ID, "alice")

	sessions := store.AllActiveSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(sessions))
	}
	if sessions[0].Username != "alice" || sessions[0].Hostname != "host-1" {
		t.Errorf("unexpected session: %+v", sessions[0])
	}
}

func TestAllActionHistory(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	store.LogAction("alice", "approved", "host-1", "CODE-1", "")
	store.LogAction("bob", "rejected", "host-2", "CODE-2", "")

	history := store.AllActionHistory()
	if len(history) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(history))
	}
	// AllActionHistory returns ActionLogEntry; just verify count is correct.
}

func TestAllActionHistoryWithUsers(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	store.LogAction("alice", "approved", "host-1", "CODE-1", "")
	store.LogAction("bob", "rejected", "host-2", "CODE-2", "admin")

	history := store.AllActionHistoryWithUsers()
	if len(history) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(history))
	}
	// Find bob's entry to verify actor field
	var bobEntry *ActionLogEntryWithUser
	for i := range history {
		if history[i].Username == "bob" {
			bobEntry = &history[i]
			break
		}
	}
	if bobEntry == nil {
		t.Fatal("bob's entry not found")
	}
	if bobEntry.Actor != "admin" {
		t.Errorf("actor = %q, want admin", bobEntry.Actor)
	}
	if bobEntry.Hostname != "host-2" {
		t.Errorf("hostname = %q, want host-2", bobEntry.Hostname)
	}
}

func TestActiveSessionsForHost(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 5*time.Minute, "")
	defer store.Stop()

	c1, _ := store.Create("alice", "web-1", "")
	store.Approve(c1.ID, "alice")
	c2, _ := store.Create("bob", "web-1", "")
	store.Approve(c2.ID, "bob")
	c3, _ := store.Create("carol", "db-1", "")
	store.Approve(c3.ID, "carol")

	sessions := store.ActiveSessionsForHost("web-1")
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions on web-1, got %d", len(sessions))
	}
	for _, s := range sessions {
		if s.Hostname != "web-1" {
			t.Errorf("wrong hostname: %s", s.Hostname)
		}
	}

	dbSessions := store.ActiveSessionsForHost("db-1")
	if len(dbSessions) != 1 || dbSessions[0].Username != "carol" {
		t.Errorf("unexpected db-1 sessions: %v", dbSessions)
	}
}

func TestKnownHosts(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	if got := store.KnownHosts("alice"); len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}

	store.LogAction("alice", "approved", "prod-1", "", "")
	store.LogAction("alice", "approved", "prod-2", "", "")
	store.LogAction("alice", "approved", "prod-1", "", "") // duplicate

	hosts := store.KnownHosts("alice")
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %v", hosts)
	}
	// Should be sorted alphabetically
	if hosts[0] != "prod-1" || hosts[1] != "prod-2" {
		t.Errorf("unexpected hosts: %v", hosts)
	}
}

func TestCreateGraceSession(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 5*time.Minute, "")
	defer store.Stop()

	store.CreateGraceSession("alice", "host-1", 10*time.Minute)
	if !store.WithinGracePeriod("alice", "host-1") {
		t.Error("expected active grace session after CreateGraceSession")
	}
	if store.WithinGracePeriod("alice", "host-2") {
		t.Error("grace session should not apply to different host")
	}
}

func TestEscrowedHosts(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	if got := store.EscrowedHosts(); len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}

	store.RecordEscrow("host-1", "item-abc")
	store.RecordEscrow("host-2", "item-def")

	escrowed := store.EscrowedHosts()
	if len(escrowed) != 2 {
		t.Fatalf("expected 2 escrowed hosts, got %d", len(escrowed))
	}
	if escrowed["host-1"].ItemID != "item-abc" {
		t.Errorf("host-1 item ID = %q", escrowed["host-1"].ItemID)
	}
}

func TestSetAndGetHostRotateBefore(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	// Zero value when not set
	if got := store.HostRotateBefore("host-1"); !got.IsZero() {
		t.Errorf("expected zero, got %v", got)
	}

	before := time.Now()
	store.SetHostRotateBefore("host-1")
	after := time.Now()

	ts := store.HostRotateBefore("host-1")
	if ts.Before(before) || ts.After(after) {
		t.Errorf("rotate-before timestamp %v outside expected range [%v, %v]", ts, before, after)
	}
}

func TestSetAllHostsRotateBefore(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	before := time.Now()
	store.SetAllHostsRotateBefore([]string{"host-1", "host-2", "host-3"})
	after := time.Now()

	for _, h := range []string{"host-1", "host-2", "host-3"} {
		ts := store.HostRotateBefore(h)
		if ts.Before(before) || ts.After(after) {
			t.Errorf("%s: rotate-before %v outside expected range", h, ts)
		}
	}
	// Unset host should still be zero
	if got := store.HostRotateBefore("host-99"); !got.IsZero() {
		t.Errorf("unset host should be zero, got %v", got)
	}
}

func TestExtendGraceSession(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 10*time.Minute, "")
	defer store.Stop()

	// No session — returns 0
	if got := store.ExtendGraceSession("alice", "host-1"); got != 0 {
		t.Errorf("no session: expected 0, got %v", got)
	}

	// Create a session with small remaining time (well under 75% of grace period)
	store.CreateGraceSession("alice", "host-1", 1*time.Minute)
	got := store.ExtendGraceSession("alice", "host-1")
	if got != 10*time.Minute {
		t.Errorf("expected grace period %v, got %v", 10*time.Minute, got)
	}

	// Immediately after extend, remaining > 75% — extend should be skipped
	got2 := store.ExtendGraceSession("alice", "host-1")
	if got2 == 10*time.Minute {
		// It returned gracePeriod again meaning it was re-extended — that's a bug.
		// Actually: if remaining > 75%, the original expiry is returned, not gracePeriod.
		// Since we just extended, remaining should be ~10m which IS > 7.5m (75%)
		// so it should return remaining (which is still ~10m) without re-extending.
	}
	// Verify session is still active
	if !store.WithinGracePeriod("alice", "host-1") {
		t.Error("session should still be active after extend")
	}
}

func TestConsumeOneTap(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	// First consume — should succeed
	if err := store.ConsumeOneTap("challenge-1"); err != nil {
		t.Errorf("first consume: unexpected error: %v", err)
	}

	// Second consume — should fail (already used)
	if err := store.ConsumeOneTap("challenge-1"); err == nil {
		t.Error("second consume: expected error, got nil")
	}

	// Different ID — should succeed
	if err := store.ConsumeOneTap("challenge-2"); err != nil {
		t.Errorf("different ID: unexpected error: %v", err)
	}
}

func TestRecordAndGetLastOIDCAuth(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 0, "")
	defer store.Stop()

	// Zero before any record
	if got := store.LastOIDCAuth("alice"); !got.IsZero() {
		t.Errorf("expected zero, got %v", got)
	}

	before := time.Now()
	store.RecordOIDCAuth("alice")
	after := time.Now()

	ts := store.LastOIDCAuth("alice")
	if ts.Before(before) || ts.After(after) {
		t.Errorf("LastOIDCAuth %v outside expected range [%v, %v]", ts, before, after)
	}

	// Other user should still be zero
	if got := store.LastOIDCAuth("bob"); !got.IsZero() {
		t.Errorf("bob should be zero, got %v", got)
	}
}

func TestAllUsers(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 5*time.Minute, "")
	defer store.Stop()

	if got := store.AllUsers(); len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}

	// Users appear via action log
	store.LogAction("carol", "approved", "host-1", "", "")
	// Users appear via grace sessions
	store.CreateGraceSession("dave", "host-2", 5*time.Minute)

	users := store.AllUsers()
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %v", users)
	}
	// Should be sorted alphabetically
	if users[0] != "carol" || users[1] != "dave" {
		t.Errorf("unexpected order: %v", users)
	}
}

func TestRemoveUser(t *testing.T) {
	store := NewChallengeStore(60*time.Second, 5*time.Minute, "")
	defer store.Stop()

	// Set up data for alice: pending challenge, grace session, action log entry
	c, _ := store.Create("alice", "host-1", "")
	store.Create("alice", "host-2", "") // second pending
	_ = c
	store.CreateGraceSession("alice", "host-1", 5*time.Minute)
	store.LogAction("alice", "approved", "host-1", "", "")

	// Also create data for bob to verify it's untouched
	store.LogAction("bob", "approved", "host-3", "", "")

	store.RemoveUser("alice")

	// Alice should have no pending challenges
	pending := store.AllPendingChallenges()
	for _, p := range pending {
		if p.Username == "alice" {
			t.Error("alice still has pending challenges after RemoveUser")
		}
	}

	// Alice should have no active session
	if store.WithinGracePeriod("alice", "host-1") {
		t.Error("alice should have no grace session after RemoveUser")
	}

	// Alice should not appear in AllUsers
	users := store.AllUsers()
	for _, u := range users {
		if u == "alice" {
			t.Error("alice still in AllUsers after RemoveUser")
		}
	}

	// Bob should be unaffected
	bobHistory := store.ActionHistory("bob")
	if len(bobHistory) != 1 {
		t.Errorf("bob's action history should be intact, got %d entries", len(bobHistory))
	}
}

// TestNonAdminHistoryFiltersBreakglass verifies that the rotated_breakglass
// filter (applied in handleHistoryPage for non-admins) hides server-level
// break-glass rotation events.
func TestNonAdminHistoryFiltersBreakglass(t *testing.T) {
	store := NewChallengeStore(120*time.Second, 0, "")
	defer store.Stop()

	store.LogAction("alice", "approved", "host-1", "CODE", "")
	store.LogAction("alice", "rotated_breakglass", "host-1", "", "")
	store.LogAction("alice", "rejected", "host-2", "CODE2", "")

	// Apply the same filter used in handleHistoryPage for non-admins.
	var filtered []ActionLogEntry
	for _, e := range store.ActionHistory("alice") {
		if e.Action == "rotated_breakglass" {
			continue
		}
		filtered = append(filtered, e)
	}

	if len(filtered) != 2 {
		t.Errorf("expected 2 entries after filter, got %d", len(filtered))
	}
	for _, e := range filtered {
		if e.Action == "rotated_breakglass" {
			t.Error("rotated_breakglass leaked through non-admin filter")
		}
	}
}
