package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLooksLikeID(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"5hgz4b7yeeirkjmob6h2hbngby", true},  // 26-char base32-style
		{"f5fvggxzukmks7pybjdvm6gbq4", true},  // 26-char base32-style
		{"550e8400-e29b-41d4-a716-446655440000", true}, // UUID
		{"abcdefghij1234567890", true},                 // exactly 20 chars
		{"abcdefghij1234567890123456789012345", true},  // exactly 35 chars
		{"abcdefghij12345678901234567890123456", true}, // exactly 36 chars
		{"abcdefghij123456789012345678901234567", false}, // 37 chars — too long
		{"short", false},                               // too short
		{"has a space 1234567890123", false},            // contains space
		{"has_underscore123456789012", false},           // underscore not allowed
		{"My Personal Vault", false},                   // human name — spaces
	}
	for _, tc := range tests {
		got := looksLikeID(tc.in)
		if got != tc.want {
			t.Errorf("looksLikeID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNewEscrowBackendFactory(t *testing.T) {
	tests := []struct {
		backend  string
		wantType string
	}{
		{"1password-connect", "*main.opConnectBackend"},
		{"vault", "*main.hcVaultBackend"},
		{"bitwarden", "*main.bitwardenBackend"},
		{"infisical", "*main.infisicalBackend"},
		{"", "<nil>"},
	}
	for _, tc := range tests {
		cfg := &Config{
			EscrowBackend:    tc.backend,
			EscrowURL:        "http://localhost:8080",
			EscrowAuthSecret: "tok",
			EscrowPath:       "vault-id",
		}
		b := newEscrowBackend(cfg)
		var gotType string
		if b == nil {
			gotType = "<nil>"
		} else {
			// Use a type switch instead of reflect to avoid import
			switch b.(type) {
			case *opConnectBackend:
				gotType = "*main.opConnectBackend"
			case *hcVaultBackend:
				gotType = "*main.hcVaultBackend"
			case *bitwardenBackend:
				gotType = "*main.bitwardenBackend"
			case *infisicalBackend:
				gotType = "*main.infisicalBackend"
			default:
				gotType = "unknown"
			}
		}
		if gotType != tc.wantType {
			t.Errorf("backend=%q: got type %s, want %s", tc.backend, gotType, tc.wantType)
		}
	}
}

// TestOpConnectBackendCreate verifies the 1password-connect backend creates a
// new item when none exists.
func TestOpConnectBackendCreate(t *testing.T) {
	const vaultID = "aaaabbbbccccddddeeee0000"
	const itemID = "zzzz1111222233334444ffff"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/vaults/"+vaultID+"/items":
			// No existing item
			json.NewEncoder(w).Encode([]struct{}{})
		case r.Method == "POST" && r.URL.Path == "/v1/vaults/"+vaultID+"/items":
			json.NewEncoder(w).Encode(map[string]string{"id": itemID})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	b := &opConnectBackend{
		baseURL: srv.URL,
		token:   "test-token",
		vault:   vaultID, // already an ID — skips GET /v1/vaults
		client:  newEscrowHTTPClient(),
	}

	id, vid, err := b.Store(context.Background(), "web-prod-1", "s3cr3t", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if id != itemID {
		t.Errorf("itemID = %q, want %q", id, itemID)
	}
	if vid != vaultID {
		t.Errorf("vaultID = %q, want %q", vid, vaultID)
	}
}

// TestOpConnectBackendUpdate verifies the backend updates an existing item.
func TestOpConnectBackendUpdate(t *testing.T) {
	const vaultID = "aaaabbbbccccddddeeee0000"
	const existingID = "existingid00000000000001"
	const updatedID = "existingid00000000000001"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/vaults/"+vaultID+"/items"):
			json.NewEncoder(w).Encode([]map[string]string{{"id": existingID}})
		case r.Method == "PUT" && r.URL.Path == "/v1/vaults/"+vaultID+"/items/"+existingID:
			json.NewEncoder(w).Encode(map[string]string{"id": updatedID})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	b := &opConnectBackend{
		baseURL: srv.URL,
		token:   "test-token",
		vault:   vaultID,
		client:  newEscrowHTTPClient(),
	}

	id, vid, err := b.Store(context.Background(), "web-prod-1", "newpassword", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if id != updatedID {
		t.Errorf("itemID = %q, want %q", id, updatedID)
	}
	if vid != vaultID {
		t.Errorf("vaultID = %q, want %q", vid, vaultID)
	}
}

// TestOpConnectBackendResolveVaultByName verifies that a non-ID vault name
// triggers a GET /v1/vaults lookup.
func TestOpConnectBackendResolveVaultByName(t *testing.T) {
	const vaultID = "aaaabbbbccccddddeeee0000"
	const itemID = "newitem0000000000000001a"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/vaults":
			json.NewEncoder(w).Encode([]map[string]string{
				{"id": vaultID, "name": "My Vault"},
			})
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/items"):
			json.NewEncoder(w).Encode([]struct{}{})
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/items"):
			json.NewEncoder(w).Encode(map[string]string{"id": itemID})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	b := &opConnectBackend{
		baseURL: srv.URL,
		token:   "tok",
		vault:   "My Vault", // name, not ID — triggers lookup
		client:  newEscrowHTTPClient(),
	}

	id, vid, err := b.Store(context.Background(), "db-1", "pw", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if id != itemID {
		t.Errorf("itemID = %q, want %q", id, itemID)
	}
	if vid != vaultID {
		t.Errorf("vaultID = %q, want %q", vid, vaultID)
	}
}

// TestHCVaultBackendDirectToken verifies the Vault backend uses a direct token
// (no AppRole) when EscrowAuthID is empty.
func TestHCVaultBackendDirectToken(t *testing.T) {
	writeCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "root-token" {
			t.Errorf("expected X-Vault-Token: root-token, got %q", r.Header.Get("X-Vault-Token"))
		}
		if r.Method == "POST" || r.Method == "PUT" {
			writeCount++
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{}})
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer srv.Close()

	b := &hcVaultBackend{
		baseURL:  srv.URL,
		roleID:   "", // empty → direct token mode
		secretID: "root-token",
		path:     "secret/pam",
		client:   newEscrowHTTPClient(),
	}

	itemID, _, err := b.Store(context.Background(), "host-1", "password", "")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if !strings.Contains(itemID, "/v1/secret/data/pam/host-1") {
		t.Errorf("itemID = %q, want to contain /v1/secret/data/pam/host-1", itemID)
	}
	if writeCount == 0 {
		t.Error("expected at least one write request")
	}
}

// TestResolveEscrowVault covers the hostname→vault routing logic.
func TestResolveEscrowVault(t *testing.T) {
	vaultMap := map[string]string{
		"web-*":        "web-vault",
		"db-*":         "db-vault",
		"db-primary":   "db-primary-vault", // more specific exact match
		"*-prod":       "prod-vault",
		"default":      "default-vault",
	}
	tests := []struct {
		hostname string
		want     string
	}{
		{"db-primary", "db-primary-vault"},   // exact beats glob
		{"web-frontend", "web-vault"},         // prefix glob
		{"web-backend", "web-vault"},          // prefix glob
		{"db-replica", "db-vault"},            // prefix glob
		{"api-prod", "prod-vault"},            // suffix glob
		{"unknown-host", "default-vault"},     // "default" key fallback
		{"web-api-prod", "prod-vault"},         // both web-* and *-prod match; *-prod (6 chars) beats web-* (5 chars)
	}
	for _, tc := range tests {
		got := resolveEscrowVault(tc.hostname, vaultMap, "global-vault")
		if got != tc.want {
			t.Errorf("resolveEscrowVault(%q) = %q, want %q", tc.hostname, got, tc.want)
		}
	}

	// Empty map falls back to defaultVault
	if got := resolveEscrowVault("anything", nil, "global-vault"); got != "global-vault" {
		t.Errorf("empty map: got %q, want global-vault", got)
	}

	// No match and no "default" key falls back to defaultVault
	sparse := map[string]string{"web-*": "web-vault"}
	if got := resolveEscrowVault("db-1", sparse, "global-vault"); got != "global-vault" {
		t.Errorf("no match: got %q, want global-vault", got)
	}
}

// TestOpConnectVaultOverride verifies Store uses the vault parameter over b.vault.
func TestOpConnectVaultOverride(t *testing.T) {
	const defaultVault = "default-vault-id00000000"
	const overrideVault = "override-vault-id000000"
	const itemID = "newitem0000000000000002b"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/"+overrideVault+"/items"):
			json.NewEncoder(w).Encode([]struct{}{})
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/"+overrideVault+"/items"):
			json.NewEncoder(w).Encode(map[string]string{"id": itemID})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	b := &opConnectBackend{
		baseURL: srv.URL,
		token:   "tok",
		vault:   defaultVault,
		client:  newEscrowHTTPClient(),
	}

	id, vid, err := b.Store(context.Background(), "host-1", "pw", overrideVault)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if id != itemID {
		t.Errorf("itemID = %q, want %q", id, itemID)
	}
	if vid != overrideVault {
		t.Errorf("vaultID = %q, want %q", vid, overrideVault)
	}
}
