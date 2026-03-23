package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// RegisteredHost represents a host authorized to use pam-pocketid.
type RegisteredHost struct {
	Secret       string    `json:"secret"`
	Users        []string  `json:"users"`             // authorized usernames, "*" = all users
	Group        string    `json:"group,omitempty"`   // e.g., "production", "staging", "dev"
	RegisteredAt time.Time `json:"registered_at"`
}

// HostRegistry manages registered hosts with per-host secrets.
type HostRegistry struct {
	mu       sync.RWMutex
	hosts    map[string]*RegisteredHost // hostname -> config
	filePath string
}

// NewHostRegistry creates a new host registry, loading any existing data from filePath.
func NewHostRegistry(filePath string) *HostRegistry {
	r := &HostRegistry{
		hosts:    make(map[string]*RegisteredHost),
		filePath: filePath,
	}
	if filePath != "" {
		r.load()
	}
	return r
}

// IsEnabled returns true if any hosts are registered.
// When no hosts are registered, the server falls back to global shared secret.
func (r *HostRegistry) IsEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.hosts) > 0
}

// ValidateHost checks if a hostname is registered and the secret matches.
// Returns true if validation passes. When the registry is empty (no hosts
// registered), returns true for backward compatibility.
func (r *HostRegistry) ValidateHost(hostname, secret string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hosts) == 0 {
		return true // no hosts registered = backward compat
	}
	host, ok := r.hosts[hostname]
	if !ok {
		return false
	}
	// Constant-time comparison to prevent timing attacks
	return subtleCompare(host.Secret, secret)
}

// ValidateAnyHost checks if the provided secret matches any registered host.
// Used for API endpoints where the hostname isn't known at auth time (e.g., poll, grace-status).
func (r *HostRegistry) ValidateAnyHost(secret string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hosts) == 0 {
		return true
	}
	for _, host := range r.hosts {
		if subtleCompare(host.Secret, secret) {
			return true
		}
	}
	return false
}

// IsUserAuthorized checks if a username is allowed on a host.
// When the registry is empty, returns true for backward compatibility.
func (r *HostRegistry) IsUserAuthorized(hostname, username string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hosts) == 0 {
		return true
	}
	host, ok := r.hosts[hostname]
	if !ok {
		return false
	}
	for _, u := range host.Users {
		if u == "*" || u == username {
			return true
		}
	}
	return false
}

// RegisteredHosts returns all registered hostnames, sorted alphabetically.
func (r *HostRegistry) RegisteredHosts() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var hosts []string
	for h := range r.hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// GetHost returns info about a registered host (without exposing the secret).
func (r *HostRegistry) GetHost(hostname string) (users []string, group string, registeredAt time.Time, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	host, exists := r.hosts[hostname]
	if !exists {
		return nil, "", time.Time{}, false
	}
	usersCopy := make([]string, len(host.Users))
	copy(usersCopy, host.Users)
	return usersCopy, host.Group, host.RegisteredAt, true
}

// HostsForUser returns hostnames the user is authorized for, sorted alphabetically.
func (r *HostRegistry) HostsForUser(username string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []string
	for hostname, host := range r.hosts {
		for _, u := range host.Users {
			if u == "*" || u == username {
				result = append(result, hostname)
				break
			}
		}
	}
	sort.Strings(result)
	return result
}

// AddHost registers a new host with a generated secret.
// Returns the secret so the admin can configure the host.
func (r *HostRegistry) AddHost(hostname string, users []string, group string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.hosts[hostname]; exists {
		return "", fmt.Errorf("host %q is already registered", hostname)
	}
	secret, err := generateHostSecret()
	if err != nil {
		return "", fmt.Errorf("generating secret: %w", err)
	}
	r.hosts[hostname] = &RegisteredHost{
		Secret:       secret,
		Users:        users,
		Group:        group,
		RegisteredAt: time.Now(),
	}
	registeredHosts.Set(float64(len(r.hosts)))
	r.saveLocked()
	return secret, nil
}

// RemoveHost unregisters a host.
func (r *HostRegistry) RemoveHost(hostname string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.hosts[hostname]; !exists {
		return fmt.Errorf("host %q is not registered", hostname)
	}
	delete(r.hosts, hostname)
	registeredHosts.Set(float64(len(r.hosts)))
	r.saveLocked()
	return nil
}

// RotateSecret generates a new secret for a host.
// Returns the new secret.
func (r *HostRegistry) RotateSecret(hostname string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	host, exists := r.hosts[hostname]
	if !exists {
		return "", fmt.Errorf("host %q is not registered", hostname)
	}
	secret, err := generateHostSecret()
	if err != nil {
		return "", fmt.Errorf("generating secret: %w", err)
	}
	host.Secret = secret
	r.saveLocked()
	return secret, nil
}

// generateHostSecret generates a cryptographically random 64-character hex secret.
func generateHostSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (r *HostRegistry) load() {
	data, err := os.ReadFile(r.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("WARNING: cannot read host registry %s: %v", r.filePath, err)
		}
		return
	}
	var hosts map[string]*RegisteredHost
	if err := json.Unmarshal(data, &hosts); err != nil {
		log.Printf("WARNING: corrupt host registry %s: %v — starting fresh", r.filePath, err)
		return
	}
	// Filter out nil entries that could cause panics
	for hostname, host := range hosts {
		if host == nil {
			log.Printf("WARNING: host registry contains nil entry for %q — skipping", hostname)
			delete(hosts, hostname)
		}
	}
	if hosts != nil {
		r.hosts = hosts
	}
	log.Printf("Loaded %d registered hosts from %s", len(hosts), r.filePath)
	registeredHosts.Set(float64(len(r.hosts)))
}

func (r *HostRegistry) saveLocked() {
	if r.filePath == "" {
		return
	}
	data, err := json.MarshalIndent(r.hosts, "", "  ")
	if err != nil {
		log.Printf("ERROR: marshaling host registry: %v", err)
		return
	}
	// Atomic write: temp file + fsync + rename
	dir := r.filePath[:strings.LastIndex(r.filePath, "/")+1]
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".hosts-tmp-*")
	if err != nil {
		log.Printf("ERROR: creating temp host registry file: %v", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		log.Printf("ERROR: writing host registry: %v", err)
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		log.Printf("ERROR: syncing host registry: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		log.Printf("ERROR: closing host registry temp file: %v", err)
		return
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		log.Printf("ERROR: setting host registry permissions: %v", err)
		return
	}
	if err := os.Rename(tmpName, r.filePath); err != nil {
		os.Remove(tmpName)
		log.Printf("ERROR: renaming host registry: %v", err)
	}
}

// subtleCompare does constant-time string comparison, preventing timing attacks.
// Hashes both values before comparison to prevent length leakage.
func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		// Hash both to prevent length leakage
		ha := sha256.Sum256([]byte(a))
		hb := sha256.Sum256([]byte(b))
		return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
