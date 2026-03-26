package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
)

var sshKeyClaimRe = regexp.MustCompile(`^sshPublicKey\d*$`)

// PocketIDClient fetches user and group data from the Pocket ID REST API.
type PocketIDClient struct {
	baseURL string
	apiKey  string
	client  *http.Client

	mu          sync.RWMutex
	cachedData  *pocketIDData
	cacheExpiry time.Time
	cacheTTL    time.Duration
	fetchMu     sync.Mutex // separate from cache mu; serializes fetches
}

type pocketIDData struct {
	Groups []pocketIDGroup
	// Keyed by username for fast lookup
	UserGroups map[string][]pocketIDGroupInfo
}

type pocketIDGroup struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	CustomClaims []pocketIDClaim `json:"customClaims"`
	Users        []pocketIDUser  `json:"users"`
}

type pocketIDClaim struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type pocketIDUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// pocketIDGroupInfo is the per-user view of a group's permissions
type pocketIDGroupInfo struct {
	Name         string
	SudoCommands string // from sudoCommands claim
	SudoHosts    string // from sudoHosts claim
	SudoRunAs    string // from sudoRunAsUser claim
	AccessHosts  string // from accessHosts claim
}

func NewPocketIDClient(baseURL, apiKey string) *PocketIDClient {
	if baseURL == "" || apiKey == "" {
		return nil
	}
	return &PocketIDClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		cacheTTL: 5 * time.Minute,
	}
}

// GetGroups returns all PocketID groups with their members and custom claims.
// Results are served from the shared 5-minute cache.
func (c *PocketIDClient) GetGroups() ([]pocketIDGroup, error) {
	if c == nil {
		return nil, nil
	}
	c.mu.RLock()
	if c.cachedData != nil && time.Now().Before(c.cacheExpiry) {
		data := c.cachedData.Groups
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	c.mu.RLock()
	if c.cachedData != nil && time.Now().Before(c.cacheExpiry) {
		data := c.cachedData.Groups
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	data, err := c.fetchGroupData()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cachedData = data
	c.cacheExpiry = time.Now().Add(c.cacheTTL)
	c.mu.Unlock()
	return data.Groups, nil
}

func (c *PocketIDClient) GetUserPermissions() (map[string][]pocketIDGroupInfo, error) {
	if c == nil {
		return nil, nil
	}

	// Check cache
	c.mu.RLock()
	if c.cachedData != nil && time.Now().Before(c.cacheExpiry) {
		data := c.cachedData.UserGroups
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	// Serialize concurrent fetches to prevent cache stampede.
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	// Re-check cache under fetch lock (another goroutine may have just refreshed).
	c.mu.RLock()
	if c.cachedData != nil && time.Now().Before(c.cacheExpiry) {
		data := c.cachedData.UserGroups
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	// Fetch fresh data
	data, err := c.fetchGroupData()
	if err != nil {
		return nil, err
	}

	// Cache it
	c.mu.Lock()
	c.cachedData = data
	c.cacheExpiry = time.Now().Add(c.cacheTTL)
	c.mu.Unlock()

	return data.UserGroups, nil
}

func (c *PocketIDClient) fetchGroupData() (*pocketIDData, error) {
	// Step 1: List all groups
	var allGroups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	page := 1
	for {
		url := fmt.Sprintf("%s/api/user-groups?pagination[page]=%d&pagination[limit]=100", c.baseURL, page)
		resp, err := c.apiGet(url)
		if err != nil {
			return nil, fmt.Errorf("listing groups: %w", err)
		}

		var result struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
			Pagination struct {
				TotalPages int `json:"totalPages"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(resp, &result); err != nil {
			// Try as plain array (some Pocket ID versions)
			if err2 := json.Unmarshal(resp, &allGroups); err2 != nil {
				return nil, fmt.Errorf("parsing groups: %w", err)
			}
			break
		}
		allGroups = append(allGroups, result.Data...)
		if page >= result.Pagination.TotalPages {
			break
		}
		page++
	}

	// Step 2: Fetch each group's details (members + custom claims)
	userGroups := make(map[string][]pocketIDGroupInfo)
	var groups []pocketIDGroup

	for _, g := range allGroups {
		url := fmt.Sprintf("%s/api/user-groups/%s", c.baseURL, g.ID)
		resp, err := c.apiGet(url)
		if err != nil {
			log.Printf("WARNING: fetching group %q: %v", g.Name, err)
			continue
		}

		var group pocketIDGroup
		if err := json.Unmarshal(resp, &group); err != nil {
			log.Printf("WARNING: parsing group %q: %v", g.Name, err)
			continue
		}

		// Parse custom claims into permissions
		claims := make(map[string]string)
		for _, cl := range group.CustomClaims {
			claims[cl.Key] = cl.Value
		}

		info := pocketIDGroupInfo{
			Name:         group.Name,
			SudoCommands: claims["sudoCommands"],
			SudoHosts:    claims["sudoHosts"],
			SudoRunAs:    claims["sudoRunAsUser"],
			AccessHosts:  claims["accessHosts"],
		}

		// Map to each member
		for _, user := range group.Users {
			userGroups[user.Username] = append(userGroups[user.Username], info)
		}

		groups = append(groups, group)
	}

	return &pocketIDData{Groups: groups, UserGroups: userGroups}, nil
}

// SSHUser is a PocketID user who has at least one sshPublicKey* custom claim.
type SSHUser struct {
	Username string
	Email    string
}

// UsersWithSSHKeys returns all PocketID users who have at least one non-empty
// sshPublicKey* custom claim (sshPublicKey, sshPublicKey1 … sshPublicKey99).
// Results are NOT cached — the deploy modal always needs fresh data.
func (c *PocketIDClient) UsersWithSSHKeys() ([]SSHUser, error) {
	if c == nil {
		return nil, nil
	}

	var out []SSHUser
	page := 1
	for {
		url := fmt.Sprintf("%s/api/users?pagination[page]=%d&pagination[limit]=100", c.baseURL, page)
		resp, err := c.apiGet(url)
		if err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}

		var result struct {
			Data []struct {
				Username     string          `json:"username"`
				Email        string          `json:"email"`
				CustomClaims []pocketIDClaim `json:"customClaims"`
			} `json:"data"`
			Pagination struct {
				TotalPages int `json:"totalPages"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(resp, &result); err != nil {
			return nil, fmt.Errorf("parsing users: %w", err)
		}

		for _, u := range result.Data {
			for _, cl := range u.CustomClaims {
				if sshKeyClaimRe.MatchString(cl.Key) && cl.Value != "" {
					out = append(out, SSHUser{Username: u.Username, Email: u.Email})
					break
				}
			}
		}

		if page >= result.Pagination.TotalPages || result.Pagination.TotalPages == 0 {
			break
		}
		page++
	}
	return out, nil
}

func (c *PocketIDClient) apiGet(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
}
