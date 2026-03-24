package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// PocketIDClient fetches user and group data from the Pocket ID REST API.
type PocketIDClient struct {
	baseURL string
	apiKey  string
	client  *http.Client

	mu          sync.RWMutex
	cachedData  *pocketIDData
	cacheExpiry time.Time
	cacheTTL    time.Duration
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
		baseURL:  baseURL,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 10 * time.Second},
		cacheTTL: 5 * time.Minute,
	}
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
	}

	return &pocketIDData{UserGroups: userGroups}, nil
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
