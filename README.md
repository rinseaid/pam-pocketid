# pam-pocketid

Browser-based sudo elevation via [Pocket ID](https://github.com/pocket-id/pocket-id). When a user runs `sudo`, they're shown a URL and code — authenticate with a passkey in the browser, and sudo proceeds. No passwords required.

## How it works

```
 Terminal                    pam-pocketid server             Pocket ID
    |                               |                            |
    | ---- POST /challenge -------> |                            |
    |      {user: jordan}           |                            |
    |                               |                            |
    | <----- url + code ----------- |                            |
    |                               |                            |
    | "Approve at:                  |                            |
    |  sudo.example.com/            |                            |
    |  approve/ABCDEF-123456"       |                            |
    |                               |                            |
    |    User opens URL ----------> | Approval page              |
    |                               |                            |
    |                               | ---- OIDC auth code -----> |
    |                               |                            |
    |                               |              Passkey login |
    |                               |                            |
    |                               | <--- callback (id_token) - |
    |                               |                            |
    |                               | Verify: username matches   |
    |                               | Challenge approved         |
    |                               |                            |
    | <---- poll: approved -------- |                            |
    |                               |                            |
    sudo proceeds                   |                            |
```

Two components:
1. **Server** (`pam-pocketid serve`) — OIDC relay that manages challenges and handles browser auth
2. **PAM helper** (`pam-pocketid`) — called by `pam_exec`, creates challenge, shows URL, polls for approval

## Quick start

### 1. Register an OIDC app in Pocket ID

Create a new OIDC client in Pocket ID:
- **Redirect URI**: `https://sudo.example.com/callback`
- **Scopes**: `openid`, `profile`, `email`

Note the client ID and secret.

### 2. Run the server

```yaml
services:
  pam-pocketid:
    image: ghcr.io/rinseaid/pam-pocketid:latest
    ports:
      - "8090:8090"
    environment:
      PAM_POCKETID_ISSUER_URL: "https://id.example.com"
      PAM_POCKETID_CLIENT_ID: "your-oidc-client-id"
      PAM_POCKETID_CLIENT_SECRET: "your-oidc-client-secret"
      PAM_POCKETID_EXTERNAL_URL: "https://sudo.example.com"
      PAM_POCKETID_SHARED_SECRET: "your-shared-secret"
    restart: unless-stopped
```

### 3. Install the PAM helper on Linux hosts

Copy the `pam-pocketid` binary to each managed host:

```bash
# Download from releases
curl -L -o /usr/local/bin/pam-pocketid \
  https://github.com/rinseaid/pam-pocketid/releases/latest/download/pam-pocketid-linux-amd64
chmod +x /usr/local/bin/pam-pocketid
```

Configure the helper:

```bash
cat > /etc/environment.d/pam-pocketid.conf <<EOF
PAM_POCKETID_SERVER_URL=https://sudo.example.com
PAM_POCKETID_SHARED_SECRET=your-shared-secret
EOF
```

### 4. Configure PAM

Edit `/etc/pam.d/sudo`:

```
# Pocket ID browser-based authentication
auth    required    pam_exec.so    expose_authtok stdout /usr/local/bin/pam-pocketid

account required    pam_unix.so
session required    pam_limits.so
```

### 5. Configure glauth-pocketid for PAM-based sudo auth

In glauth-pocketid, leave `POCKETID_SUDO_NO_AUTHENTICATE` at its default value (`false`). This ensures sudo rules do **not** include `!authenticate`, so sudo will invoke the PAM stack — which now routes through pam-pocketid for browser-based passkey approval instead of asking for a password.

If you previously set `POCKETID_SUDO_NO_AUTHENTICATE=true`, remove it or set it to `false`. Also remove any `sudoOptions=!authenticate` from your Pocket ID group claims.

## What the user sees

```
$ sudo apt update

  Sudo elevation requires Pocket ID approval.
  Approve at: https://sudo.example.com/approve/ABCD-1234
  Code: ABCD-1234

  Waiting for approval (expires in 120s)...
  Approved!

[sudo] runs the command
```

## Configuration

### Server environment variables

| Variable | Default | Description |
|---|---|---|
| `PAM_POCKETID_ISSUER_URL` | *(required)* | Pocket ID OIDC issuer URL |
| `PAM_POCKETID_CLIENT_ID` | *(required)* | OIDC client ID |
| `PAM_POCKETID_CLIENT_SECRET` | *(required)* | OIDC client secret |
| `PAM_POCKETID_EXTERNAL_URL` | *(required)* | Public URL of this server |
| `PAM_POCKETID_LISTEN` | `:8090` | Listen address |
| `PAM_POCKETID_CHALLENGE_TTL` | `120` | Challenge lifetime in seconds |
| `PAM_POCKETID_SHARED_SECRET` | *(empty)* | Shared secret for PAM helper auth |

### PAM helper environment variables

| Variable | Default | Description |
|---|---|---|
| `PAM_POCKETID_SERVER_URL` | *(required)* | URL of the pam-pocketid server |
| `PAM_POCKETID_SHARED_SECRET` | *(empty)* | Shared secret (must match server) |
| `PAM_POCKETID_POLL_MS` | `2000` | Poll interval in milliseconds |
| `PAM_POCKETID_TIMEOUT` | `120` | Max seconds to wait for approval |

## Integration with glauth-pocketid

This project is designed to work alongside [glauth-pocketid](https://github.com/rinseaid/glauth-pocketid). Together they provide a complete passwordless Linux host management stack:

| Component | Role |
|---|---|
| **Pocket ID** | Identity provider — users, groups, passkeys, custom claims |
| **glauth-pocketid** | LDAP bridge — translates Pocket ID users/groups into POSIX accounts, sudo rules, SSH keys |
| **sssd** | Linux client — resolves users/groups via LDAP, delivers sudo rules and SSH keys |
| **pam-pocketid** | sudo auth — browser-based passkey approval when running sudo |

glauth-pocketid defines *what* users can sudo (commands, hosts, run-as user). pam-pocketid defines *how* they authenticate — via passkey in a browser instead of a password.

### How sudo authentication works

When a user runs `sudo`, the `sudoRole` LDAP entries (synthesized by glauth-pocketid) determine what commands they're allowed to run. Then sudo needs to verify who they are:

- If the sudo rule includes `!authenticate`, sudo **skips verification entirely** and runs the command
- If the sudo rule does **not** include `!authenticate`, sudo **invokes the PAM auth stack**

With pam-pocketid installed in the PAM stack, the "invoke PAM" step becomes a browser-based passkey approval instead of a password prompt. The user sees a URL, opens it, taps their passkey, and sudo proceeds.

glauth-pocketid controls whether `!authenticate` appears in sudo rules via `POCKETID_SUDO_NO_AUTHENTICATE`:

| Setting | Behavior | Use with pam-pocketid? |
|---|---|---|
| `false` (default) | Sudo always invokes PAM | **Yes — recommended.** Every sudo invocation requires passkey approval. |
| `true` | Sudo never invokes PAM (`!authenticate` on all rules) | No — pam-pocketid is bypassed entirely. |
| `claims` | Per-group: groups with `sudoOptions=!authenticate` skip PAM, others invoke it | Partial — some groups use passkey auth, others skip it. |

The recommended setup is `false` (the default) + pam-pocketid. This gives you per-invocation identity verification via passkey with zero passwords in the entire chain.

### Full stack Docker Compose

Run both services on your infrastructure. Pocket ID itself can be self-hosted or managed separately.

```yaml
# docker-compose.yml — glauth-pocketid + pam-pocketid
services:
  glauth:
    image: ghcr.io/rinseaid/glauth-pocketid:latest
    ports:
      - "3893:3893"    # LDAP
      - "8080:8080"    # webhook + metrics
    environment:
      POCKETID_BASE_URL: "https://id.example.com"
      POCKETID_API_KEY: "your-pocket-id-api-key"
      POCKETID_REFRESH_SEC: "300"
      POCKETID_PERSIST_PATH: "/var/lib/glauth/uidmap.json"
      POCKETID_WEBHOOK_PORT: "8080"
      # POCKETID_SUDO_NO_AUTHENTICATE is false by default —
      # pam-pocketid handles sudo auth instead
    volumes:
      - glauth-data:/var/lib/glauth
      - ./glauth.cfg:/etc/glauth/glauth.cfg:ro
    restart: unless-stopped

  pam-pocketid:
    image: ghcr.io/rinseaid/pam-pocketid:latest
    ports:
      - "8090:8090"
    environment:
      PAM_POCKETID_ISSUER_URL: "https://id.example.com"
      PAM_POCKETID_CLIENT_ID: "your-oidc-client-id"
      PAM_POCKETID_CLIENT_SECRET: "your-oidc-client-secret"
      PAM_POCKETID_EXTERNAL_URL: "https://sudo.example.com"
      PAM_POCKETID_SHARED_SECRET: "your-shared-secret"
    restart: unless-stopped

volumes:
  glauth-data:
```

### End-to-end setup walkthrough

This walkthrough assumes Pocket ID is already running at `id.example.com` and the Docker Compose stack above is deployed at `glauth.internal` (LDAP) and `sudo.example.com` (pam-pocketid server).

**Step 1: Configure Pocket ID**

1. Create an admin API key in Pocket ID (Settings > Admin API) and set it as `POCKETID_API_KEY`
2. Register an OIDC client for pam-pocketid:
   - Redirect URI: `https://sudo.example.com/callback`
   - Scopes: `openid`, `profile`, `email`
   - Note the client ID and secret for `PAM_POCKETID_CLIENT_ID` / `PAM_POCKETID_CLIENT_SECRET`
3. Add SSH public keys as user custom claims (`sshPublicKey`, `sshPublicKey2`, `sshPublicKey3`, etc.)
4. Create groups with sudo claims:
   ```
   Group: full-admins     Claims: sudoCommands=ALL, sudoHosts=ALL, sudoRunAsUser=ALL
   Group: ops-team        Claims: sudoCommands=/usr/bin/systemctl restart *,/usr/bin/journalctl
   ```
   Do **not** set `sudoOptions=!authenticate` — leave `POCKETID_SUDO_NO_AUTHENTICATE=false` (the default) so that sudo invokes pam-pocketid for passkey-based authentication.
5. Add users to the appropriate groups

**Step 2: Create `glauth.cfg`**

```toml
[ldap]
  enabled = true
  listen  = "0.0.0.0:3893"

[ldaps]
  enabled = false

[backend]
  datastore     = "plugin"
  plugin        = "/app/pocketid.so"
  pluginhandler = "NewPocketIDHandler"
  baseDN        = "dc=example,dc=com"
  nameformat    = "cn"
  groupformat   = "ou"
  sshkeyattr    = "sshPublicKey"
  anonymousdse  = true

# Service account for sssd to bind with
[[users]]
  name         = "serviceuser"
  uidnumber    = 9000
  primarygroup = 9000
  passsha256   = "REPLACE_WITH_SHA256_OF_SERVICE_ACCOUNT_PASSWORD"

[[users.capabilities]]
  action = "search"
  object = "ou=users,dc=example,dc=com"

[[groups]]
  name      = "svcaccts"
  gidnumber = 9000
```

Generate the password hash: `echo -n 'your-service-password' | sha256sum`

**Step 3: Start the stack**

```bash
docker compose up -d
```

Verify LDAP is working:
```bash
ldapsearch -x -H ldap://glauth.internal:3893 \
  -D "cn=serviceuser,ou=svcaccts,dc=example,dc=com" \
  -w 'your-service-password' \
  -b "dc=example,dc=com" "(objectClass=posixAccount)"
```

**Step 4: Configure each Linux host**

Install sssd and configure it to use GLAuth:

```ini
# /etc/sssd/sssd.conf — mode 0600, owned by root
[sssd]
services = nss, pam, sudo, ssh
domains = example.com

[domain/example.com]
id_provider     = ldap
auth_provider   = none
sudo_provider   = ldap

ldap_uri        = ldap://glauth.internal:3893
ldap_search_base = dc=example,dc=com
ldap_default_bind_dn = cn=serviceuser,ou=svcaccts,dc=example,dc=com
ldap_default_authtok = your-service-password

enumerate = true

ldap_user_object_class   = posixAccount
ldap_group_object_class  = posixGroup
ldap_user_name           = cn
ldap_user_uid_number     = uidNumber
ldap_user_gid_number     = gidNumber
ldap_user_home_directory = homeDirectory
ldap_user_shell          = loginShell
ldap_user_ssh_public_key = sshPublicKey

ldap_group_name   = ou
ldap_group_member = memberUid

ldap_sudo_search_base = ou=sudoers,dc=example,dc=com

ldap_schema = rfc2307

entry_cache_timeout = 60

[sudo]
sudo_timed = false
```

Configure NSS (`/etc/nsswitch.conf`):
```
passwd:  files sss
group:   files sss
shadow:  files sss
sudoers: files sss
```

Configure SSH key delivery (`/etc/ssh/sshd_config`):
```
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys %u
AuthorizedKeysCommandUser root
PubkeyAuthentication yes
PasswordAuthentication no
```

Auto-create home directories (`/etc/pam.d/common-session`):
```
session optional pam_mkhomedir.so skel=/etc/skel umask=0077
```

**Step 5: Install pam-pocketid on each Linux host**

```bash
# Install the PAM helper binary
curl -L -o /usr/local/bin/pam-pocketid \
  https://github.com/rinseaid/pam-pocketid/releases/latest/download/pam-pocketid-linux-amd64
chmod +x /usr/local/bin/pam-pocketid

# Configure the helper
cat > /etc/environment.d/pam-pocketid.conf <<EOF
PAM_POCKETID_SERVER_URL=https://sudo.example.com
PAM_POCKETID_SHARED_SECRET=your-shared-secret
EOF

# Configure PAM for sudo
cat > /etc/pam.d/sudo <<EOF
auth    required    pam_exec.so    expose_authtok stdout /usr/local/bin/pam-pocketid
account required    pam_unix.so
session required    pam_limits.so
EOF
```

Restart sssd and sshd:
```bash
systemctl restart sssd sshd
```

**Step 6: Verify everything works**

```bash
# User/group resolution via sssd + GLAuth
getent passwd jordan
getent group full-admins

# SSH key delivery
sss_ssh_authorizedkeys jordan

# Sudo rules
sudo -l -U jordan

# Sudo with passkey auth (will show approval URL)
sudo whoami
```

When a user runs `sudo`, they see a URL and approval code. They open the URL in a browser, authenticate with their passkey via Pocket ID, and sudo proceeds -- no password needed anywhere in the chain.

## Security considerations

- **Identity binding** — The server verifies that the OIDC-authenticated user matches the sudo user; you can't approve someone else's request
- **CSRF protection** — Each challenge has a cryptographic nonce bound server-side; the OIDC state parameter and ID token nonce are both verified against it
- **Single-use login** — Each challenge can only have its OIDC flow initiated once, preventing an attacker from re-initiating auth for another user's challenge
- **Brute-force resistance** — User codes are 13 characters (XXXXXX-YYYYYY, ~191 billion combinations), infeasible to enumerate within the TTL
- **Rate limiting** — Per-user cap (5 pending) and global cap (10,000 total) prevent memory exhaustion DoS
- **Constant-time comparison** — Shared secret verification uses `crypto/subtle` to prevent timing attacks
- **Request size limits** — API bodies capped at 1KB, PAM client responses capped at 64KB
- **Input validation** — Usernames restricted to `[a-zA-Z0-9._-]{1,64}`, challenge IDs validated as hex
- **No redirect following** — PAM client rejects HTTP redirects to prevent SSRF from privileged (root) context
- **Challenge ID isolation** — The challenge ID (used for polling) never appears in browser-facing content; approval pages use the user code instead
- **URL scheme validation** — Server and client URLs must be `https://` or `http://`
- **Challenges expire** after the configured TTL (default 120s, bounded 10s–10min)
- **No passwords** — Authentication is passkey-only at the Pocket ID layer

## Building from source

```bash
make build    # produces bin/pam-pocketid
make test     # run tests
make docker   # build container image
```

## Example files

| File | Description |
|---|---|
| [`docker-compose.example.yml`](docker-compose.example.yml) | Docker Compose stack |
| [`pam.d/sudo-pocketid`](pam.d/sudo-pocketid) | Example PAM configuration |
