package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// escrowBackend is the interface implemented by native escrow backends.
// Store saves the break-glass password for the given hostname and returns
// an opaque item identifier (URL, path, UUID, etc.) and an optional vault/
// container identifier for recording in the escrow log. Both may be empty.
type escrowBackend interface {
	Store(ctx context.Context, hostname, password string) (itemID, vaultID string, err error)
}

// newEscrowBackend returns the configured native escrow backend, or nil if
// ESCROW_BACKEND is not set (caller falls through to EscrowCommand).
func newEscrowBackend(cfg *Config) escrowBackend {
	switch cfg.EscrowBackend {
	case "1password-connect":
		return &opConnectBackend{
			baseURL: strings.TrimRight(cfg.EscrowURL, "/"),
			token:   cfg.EscrowAuthSecret,
			vault:   cfg.EscrowPath,
			client:  newEscrowHTTPClient(),
		}
	case "vault":
		return &hcVaultBackend{
			baseURL:  strings.TrimRight(cfg.EscrowURL, "/"),
			roleID:   cfg.EscrowAuthID,
			secretID: cfg.EscrowAuthSecret,
			path:     cfg.EscrowPath,
			client:   newEscrowHTTPClient(),
		}
	case "bitwarden":
		return &bitwardenBackend{
			apiURL:       strings.TrimRight(cfg.EscrowURL, "/"),
			clientID:     cfg.EscrowAuthID,
			clientSecret: cfg.EscrowAuthSecret,
			orgProject:   cfg.EscrowPath,
			client:       newEscrowHTTPClient(),
		}
	case "infisical":
		return &infisicalBackend{
			baseURL:      strings.TrimRight(cfg.EscrowURL, "/"),
			clientID:     cfg.EscrowAuthID,
			clientSecret: cfg.EscrowAuthSecret,
			projectEnv:   cfg.EscrowPath,
			client:       newEscrowHTTPClient(),
		}
	default:
		return nil
	}
}

// newEscrowHTTPClient returns a hardened HTTP client: no proxy (prevents SSRF
// via HTTP_PROXY), no redirect following, 30s timeout.
func newEscrowHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// doJSONRequest sends a JSON request and returns the response body.
// Returns an error for non-2xx responses.
func doJSONRequest(ctx context.Context, client *http.Client, method, rawURL string, body interface{}, authHeader string) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respData, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateOutput(string(respData)))
	}
	return respData, nil
}

// looksLikeID returns true if s looks like a UUID or base32 ID (alphanumeric
// and dashes only, 20–36 chars). Used to decide whether to use a value
// directly as a vault/item ID or to resolve it by name.
func looksLikeID(s string) bool {
	if len(s) < 20 || len(s) > 36 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// ─── 1Password Connect ───────────────────────────────────────────────────────

// opConnectBackend stores break-glass passwords in 1Password via Connect Server.
//
// Configuration:
//   - ESCROW_URL        = Connect Server base URL (e.g., http://localhost:8080)
//   - ESCROW_AUTH_SECRET = Connect API token
//   - ESCROW_PATH       = vault name or UUID to store items in
//
// Items are stored with title "breakglass-{hostname}". Existing items are
// updated in-place; new items are created if no match is found.
type opConnectBackend struct {
	baseURL string
	token   string
	vault   string // vault name or UUID
	client  *http.Client
}

func (b *opConnectBackend) Store(ctx context.Context, hostname, password string) (string, string, error) {
	vaultID, err := b.resolveVault(ctx)
	if err != nil {
		return "", "", fmt.Errorf("1password-connect: resolve vault: %w", err)
	}

	title := "breakglass-" + hostname

	// Search for an existing item with this title.
	existingID, err := b.findItem(ctx, vaultID, title)
	if err != nil {
		return "", "", fmt.Errorf("1password-connect: search items: %w", err)
	}

	item := map[string]interface{}{
		"vault":    map[string]string{"id": vaultID},
		"title":    title,
		"category": "LOGIN",
		"fields": []map[string]interface{}{
			{
				"id":      "password",
				"type":    "CONCEALED",
				"purpose": "PASSWORD",
				"label":   "password",
				"value":   password,
			},
		},
	}

	auth := "Bearer " + b.token
	var itemID string
	if existingID != "" {
		path := fmt.Sprintf("%s/v1/vaults/%s/items/%s", b.baseURL, vaultID, existingID)
		respData, err := doJSONRequest(ctx, b.client, "PUT", path, item, auth)
		if err != nil {
			return "", "", fmt.Errorf("1password-connect: update item: %w", err)
		}
		var updated struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(respData, &updated); err != nil {
			return "", "", fmt.Errorf("1password-connect: parse update response: %w", err)
		}
		itemID = updated.ID
	} else {
		path := fmt.Sprintf("%s/v1/vaults/%s/items", b.baseURL, vaultID)
		respData, err := doJSONRequest(ctx, b.client, "POST", path, item, auth)
		if err != nil {
			return "", "", fmt.Errorf("1password-connect: create item: %w", err)
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(respData, &created); err != nil {
			return "", "", fmt.Errorf("1password-connect: parse create response: %w", err)
		}
		itemID = created.ID
	}
	// Return the resolved vault UUID so callers can construct web UI links.
	return itemID, vaultID, nil
}

func (b *opConnectBackend) resolveVault(ctx context.Context) (string, error) {
	if looksLikeID(b.vault) {
		return b.vault, nil
	}
	respData, err := doJSONRequest(ctx, b.client, "GET", b.baseURL+"/v1/vaults", nil, "Bearer "+b.token)
	if err != nil {
		return "", err
	}
	var vaults []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(respData, &vaults); err != nil {
		return "", fmt.Errorf("parsing vaults: %w", err)
	}
	for _, v := range vaults {
		if strings.EqualFold(v.Name, b.vault) {
			return v.ID, nil
		}
	}
	return "", fmt.Errorf("vault %q not found", b.vault)
}

func (b *opConnectBackend) findItem(ctx context.Context, vaultID, title string) (string, error) {
	filter := `title eq "` + title + `"`
	path := fmt.Sprintf("%s/v1/vaults/%s/items?filter=%s", b.baseURL, vaultID, url.QueryEscape(filter))
	respData, err := doJSONRequest(ctx, b.client, "GET", path, nil, "Bearer "+b.token)
	if err != nil {
		return "", err
	}
	var items []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respData, &items); err != nil {
		return "", fmt.Errorf("parsing items: %w", err)
	}
	if len(items) > 0 {
		return items[0].ID, nil
	}
	return "", nil
}

// ─── HashiCorp Vault ──────────────────────────────────────────────────────────

// hcVaultBackend stores break-glass passwords in HashiCorp Vault (KV v2).
//
// Configuration:
//   - ESCROW_URL         = Vault server URL (e.g., https://vault:8200)
//   - ESCROW_AUTH_ID     = AppRole role_id; omit to use ESCROW_AUTH_SECRET as a direct token
//   - ESCROW_AUTH_SECRET = AppRole secret_id, or direct Vault token when AUTH_ID is empty
//   - ESCROW_PATH        = KV mount + path prefix (e.g., "secret/pam-pocketid")
//
// Passwords are stored at {mount}/data/{prefix}/{hostname}.
type hcVaultBackend struct {
	baseURL  string
	roleID   string
	secretID string
	path     string
	client   *http.Client
}

func (b *hcVaultBackend) Store(ctx context.Context, hostname, password string) (string, string, error) {
	token, err := b.getToken(ctx)
	if err != nil {
		return "", "", fmt.Errorf("vault: auth: %w", err)
	}

	// Split path into mount + prefix. e.g., "secret/pam-pocketid" → "secret", "pam-pocketid"
	mount, prefix, hasPrefix := strings.Cut(b.path, "/")
	var kvPath string
	if hasPrefix {
		kvPath = fmt.Sprintf("/v1/%s/data/%s/%s", mount, prefix, hostname)
	} else {
		kvPath = fmt.Sprintf("/v1/%s/data/%s", mount, hostname)
	}

	payload := map[string]interface{}{
		"data": map[string]string{"password": password},
	}
	// Vault uses X-Vault-Token for auth; use doJSONRequest with the token as Bearer
	// (we repurpose the auth header field and set the correct header in a wrapper).
	if err := b.writeSecret(ctx, kvPath, token, payload); err != nil {
		return "", "", fmt.Errorf("vault: write secret: %w", err)
	}
	return b.baseURL + kvPath, "", nil
}

// writeSecret writes to Vault KV v2, trying POST then PUT (some Vault versions
// require PUT for updates).
func (b *hcVaultBackend) writeSecret(ctx context.Context, kvPath, token string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	for _, method := range []string{"POST", "PUT"} {
		req, err := http.NewRequestWithContext(ctx, method, b.baseURL+kvPath, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("X-Vault-Token", token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := b.client.Do(req)
		if err != nil {
			return err
		}
		respData, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode < 400 {
			return nil
		}
		if method == "PUT" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateOutput(string(respData)))
		}
		// POST failed — try PUT
	}
	return nil
}

func (b *hcVaultBackend) getToken(ctx context.Context) (string, error) {
	if b.roleID == "" {
		// Direct token auth
		return b.secretID, nil
	}
	// AppRole auth
	payload := map[string]string{
		"role_id":   b.roleID,
		"secret_id": b.secretID,
	}
	respData, err := doJSONRequest(ctx, b.client, "POST", b.baseURL+"/v1/auth/approle/login", payload, "")
	if err != nil {
		return "", fmt.Errorf("approle login: %w", err)
	}
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(respData, &result); err != nil {
		return "", fmt.Errorf("parsing approle response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("approle login returned empty token")
	}
	return result.Auth.ClientToken, nil
}

// ─── Bitwarden Secrets Manager ────────────────────────────────────────────────

// bitwardenBackend stores break-glass passwords in Bitwarden Secrets Manager.
//
// Configuration:
//   - ESCROW_URL         = Bitwarden API base URL (e.g., https://api.bitwarden.com)
//   - ESCROW_AUTH_ID     = Service account client_id
//   - ESCROW_AUTH_SECRET = Service account client_secret
//   - ESCROW_PATH        = "{organizationId}" or "{organizationId}/{projectId}"
//
// The identity server URL is derived from the API URL:
//   - https://api.bitwarden.com → https://identity.bitwarden.com
//   - https://example.com/api   → https://example.com/identity
//
// Secrets are stored with key "breakglass-{hostname}".
type bitwardenBackend struct {
	apiURL       string
	clientID     string
	clientSecret string
	orgProject   string // "{orgId}" or "{orgId}/{projectId}"
	client       *http.Client
}

func (b *bitwardenBackend) identityURL() string {
	// Cloud: https://api.bitwarden.com → https://identity.bitwarden.com
	if strings.Contains(b.apiURL, "api.bitwarden.com") {
		return strings.Replace(b.apiURL, "api.bitwarden.com", "identity.bitwarden.com", 1)
	}
	// Self-hosted: strip trailing /api and append /identity
	base := strings.TrimSuffix(b.apiURL, "/api")
	return base + "/identity"
}

func (b *bitwardenBackend) Store(ctx context.Context, hostname, password string) (string, string, error) {
	accessToken, err := b.getToken(ctx)
	if err != nil {
		return "", "", fmt.Errorf("bitwarden: auth: %w", err)
	}

	orgID, projectID, _ := strings.Cut(b.orgProject, "/")
	key := "breakglass-" + hostname
	auth := "Bearer " + accessToken

	// Check for existing secret
	existingID, err := b.findSecret(ctx, orgID, key, auth)
	if err != nil {
		return "", "", fmt.Errorf("bitwarden: search secrets: %w", err)
	}

	var secretID string
	if existingID != "" {
		// Update existing
		payload := map[string]interface{}{
			"key":            key,
			"value":          password,
			"organizationId": orgID,
		}
		if projectID != "" {
			payload["projectIds"] = []string{projectID}
		}
		respData, err := doJSONRequest(ctx, b.client, "PUT", b.apiURL+"/secrets/"+existingID, payload, auth)
		if err != nil {
			return "", "", fmt.Errorf("bitwarden: update secret: %w", err)
		}
		var updated struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(respData, &updated); err != nil {
			return "", "", fmt.Errorf("bitwarden: parse update response: %w", err)
		}
		secretID = updated.ID
	} else {
		// Create new
		payload := map[string]interface{}{
			"key":            key,
			"value":          password,
			"organizationId": orgID,
		}
		if projectID != "" {
			payload["projectIds"] = []string{projectID}
		}
		respData, err := doJSONRequest(ctx, b.client, "POST", b.apiURL+"/secrets", payload, auth)
		if err != nil {
			return "", "", fmt.Errorf("bitwarden: create secret: %w", err)
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(respData, &created); err != nil {
			return "", "", fmt.Errorf("bitwarden: parse create response: %w", err)
		}
		secretID = created.ID
	}
	return secretID, "", nil
}

func (b *bitwardenBackend) getToken(ctx context.Context) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", b.clientID)
	data.Set("client_secret", b.clientSecret)
	data.Set("scope", "api.secrets")

	req, err := http.NewRequestWithContext(ctx, "POST", b.identityURL()+"/connect/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := b.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respData, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("token request HTTP %d: %s", resp.StatusCode, truncateOutput(string(respData)))
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(respData, &result); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("token response contained no access_token")
	}
	return result.AccessToken, nil
}

func (b *bitwardenBackend) findSecret(ctx context.Context, orgID, key, auth string) (string, error) {
	path := fmt.Sprintf("%s/organizations/%s/secrets?search=%s", b.apiURL, orgID, url.QueryEscape(key))
	respData, err := doJSONRequest(ctx, b.client, "GET", path, nil, auth)
	if err != nil {
		return "", err
	}
	var result struct {
		Data []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respData, &result); err != nil {
		return "", fmt.Errorf("parsing secrets list: %w", err)
	}
	for _, s := range result.Data {
		if s.Key == key {
			return s.ID, nil
		}
	}
	return "", nil
}

// ─── Infisical ───────────────────────────────────────────────────────────────

// infisicalBackend stores break-glass passwords in Infisical.
//
// Configuration:
//   - ESCROW_URL         = Infisical URL (e.g., https://app.infisical.com)
//   - ESCROW_AUTH_ID     = Universal Auth client_id
//   - ESCROW_AUTH_SECRET = Universal Auth client_secret
//   - ESCROW_PATH        = "{workspaceId}/{environment}" (e.g., "abc123/prod")
//
// Secrets are stored with name "BREAKGLASS_{HOSTNAME_UPPER}".
type infisicalBackend struct {
	baseURL      string
	clientID     string
	clientSecret string
	projectEnv   string // "{workspaceId}/{environment}"
	client       *http.Client
}

func (b *infisicalBackend) Store(ctx context.Context, hostname, password string) (string, string, error) {
	token, err := b.getToken(ctx)
	if err != nil {
		return "", "", fmt.Errorf("infisical: auth: %w", err)
	}

	workspaceID, environment, _ := strings.Cut(b.projectEnv, "/")
	if environment == "" {
		environment = "prod"
	}

	secretName := "BREAKGLASS_" + strings.ToUpper(strings.ReplaceAll(hostname, "-", "_"))
	auth := "Bearer " + token

	// Try to update existing secret first; create if not found.
	updateURL := fmt.Sprintf("%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=/",
		b.baseURL, url.PathEscape(secretName), url.QueryEscape(workspaceID), url.QueryEscape(environment))

	payload := map[string]interface{}{
		"workspaceId":   workspaceID,
		"environment":   environment,
		"secretPath":    "/",
		"secretValue":   password,
	}

	_, err = doJSONRequest(ctx, b.client, "PATCH", updateURL, payload, auth)
	if err != nil {
		// Secret likely doesn't exist yet; create it
		createURL := fmt.Sprintf("%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=/",
			b.baseURL, url.PathEscape(secretName), url.QueryEscape(workspaceID), url.QueryEscape(environment))
		_, err2 := doJSONRequest(ctx, b.client, "POST", createURL, payload, auth)
		if err2 != nil {
			return "", "", fmt.Errorf("infisical: store secret: %w", err2)
		}
	}

	return fmt.Sprintf("%s/%s/%s", workspaceID, environment, secretName), "", nil
}

func (b *infisicalBackend) getToken(ctx context.Context) (string, error) {
	payload := map[string]string{
		"clientId":     b.clientID,
		"clientSecret": b.clientSecret,
	}
	respData, err := doJSONRequest(ctx, b.client, "POST", b.baseURL+"/api/v1/auth/universal-auth/login", payload, "")
	if err != nil {
		return "", fmt.Errorf("universal auth login: %w", err)
	}
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(respData, &result); err != nil {
		return "", fmt.Errorf("parsing auth response: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("auth response contained no accessToken")
	}
	return result.AccessToken, nil
}
