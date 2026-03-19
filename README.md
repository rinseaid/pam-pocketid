# pam-pocketid

Browser-based sudo elevation via [Pocket ID](https://github.com/pocket-id/pocket-id). When a user runs `sudo`, they're shown a URL and code — authenticate with a passkey in the browser, and sudo proceeds. No passwords required.

> **Note**: The majority of this project's code was generated using AI-powered coding tools, with human direction, design decisions, and review throughout. All features have been extensively tested by hand against real infrastructure.

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

Configure the helper via `/etc/pam-pocketid.conf`:

```bash
cat > /etc/pam-pocketid.conf <<EOF
PAM_POCKETID_SERVER_URL=https://sudo.example.com
PAM_POCKETID_SHARED_SECRET=your-shared-secret
EOF
chmod 600 /etc/pam-pocketid.conf
```

> pam-pocketid reads this config file directly — no wrapper scripts or environment variable tricks needed. Environment variables, if set, take precedence over config file values.

### 4. Configure PAM

Edit `/etc/pam.d/sudo` (and `/etc/pam.d/sudo-i` if it exists):

```
# Pocket ID browser-based authentication
auth    required    pam_exec.so    stdout /usr/local/bin/pam-pocketid

account required    pam_unix.so
session required    pam_limits.so
```

> **Important:** Do not use `expose_authtok` — that flag causes sudo to prompt for a password before invoking pam-pocketid. Since authentication is browser-based, no password is needed.
>
> On some systems, `sudo -i` uses `/etc/pam.d/sudo-i` instead of `/etc/pam.d/sudo`. If `sudo -i` still prompts for a password, copy your `/etc/pam.d/sudo` to `/etc/pam.d/sudo-i`.

### 5. Configure glauth-pocketid for PAM-based sudo auth

In glauth-pocketid, leave `POCKETID_SUDO_NO_AUTHENTICATE` at its default value (`false`). This ensures sudo rules do **not** include `!authenticate`, so sudo will invoke the PAM stack — which now routes through pam-pocketid for browser-based passkey approval instead of asking for a password.

If you previously set `POCKETID_SUDO_NO_AUTHENTICATE=true`, remove it or set it to `false`. Also remove any `sudoOptions=!authenticate` from your Pocket ID group claims.

## What the user sees

```
$ sudo apt update

  Sudo requires Pocket ID approval.
  Approve at: https://sudo.example.com/approve/ABCDEF-123456
  Code: ABCDEF-123456

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
| `PAM_POCKETID_GRACE_PERIOD` | `0` | Skip re-auth if user approved within this many seconds (0 = disabled) |
| `PAM_POCKETID_NOTIFY_COMMAND` | *(empty)* | Shell command for push notifications on new challenges |
| `PAM_POCKETID_NOTIFY_ENV` | *(empty)* | Comma-separated env var prefixes to pass to notify command |
| `PAM_POCKETID_NOTIFY_USERS_FILE` | *(empty)* | Path to JSON file mapping usernames to per-user notification URLs |
| `PAM_POCKETID_ESCROW_COMMAND` | *(empty)* | Shell command to escrow break-glass passwords |
| `PAM_POCKETID_ESCROW_ENV` | *(empty)* | Comma-separated env var prefixes to pass to escrow command |
| `PAM_POCKETID_BREAKGLASS_ROTATE_BEFORE` | *(empty)* | RFC3339 timestamp; signal clients to rotate if older |
| `PAM_POCKETID_INSECURE` | `false` | Allow unauthenticated API (not recommended) |

### PAM helper environment variables

| Variable | Default | Description |
|---|---|---|
| `PAM_POCKETID_SERVER_URL` | *(required)* | URL of the pam-pocketid server |
| `PAM_POCKETID_SHARED_SECRET` | *(empty)* | Shared secret (must match server) |
| `PAM_POCKETID_POLL_MS` | `2000` | Poll interval in milliseconds |
| `PAM_POCKETID_TIMEOUT` | `120` | Max seconds to wait for approval |
| `PAM_POCKETID_BREAKGLASS_ENABLED` | `true` | Enable break-glass fallback authentication |
| `PAM_POCKETID_BREAKGLASS_FILE` | `/etc/pam-pocketid-breakglass` | Path to break-glass bcrypt hash file |
| `PAM_POCKETID_BREAKGLASS_ROTATION_DAYS` | `90` | Automatic rotation interval in days |
| `PAM_POCKETID_BREAKGLASS_PASSWORD_TYPE` | `random` | Password type: random, passphrase, or alphanumeric |

## Push notifications

When a new sudo challenge is created, the server can run a shell command to send a push notification to your phone. This lets you tap the approval URL directly from the notification instead of copy-pasting from the terminal.

Notifications are **not** sent for grace-period auto-approvals (no action needed).

### Using Apprise (recommended)

[Apprise](https://github.com/caronc/apprise) supports 80+ notification services with a single tool. It's included in the Docker image.

```yaml
# docker-compose.yml
environment:
  PAM_POCKETID_NOTIFY_COMMAND: >-
    apprise -t "Sudo approval needed"
    -b "User: $NOTIFY_USERNAME\nHost: $NOTIFY_HOSTNAME\nCode: $NOTIFY_USER_CODE\nApprove: $NOTIFY_APPROVAL_URL\nExpires: ${NOTIFY_EXPIRES_IN}s"
    "$APPRISE_URLS"
  PAM_POCKETID_NOTIFY_ENV: "APPRISE_"
```

Set `APPRISE_URLS` to one or more notification service URLs (space-separated):

```bash
# Telegram
APPRISE_URLS="tgram://bot_token/chat_id"

# ntfy
APPRISE_URLS="ntfy://ntfy.sh/my-sudo-alerts"

# Pushover
APPRISE_URLS="pover://user_key@app_token"

# Gotify
APPRISE_URLS="gotify://gotify.example.com/token"

# Multiple services at once
APPRISE_URLS="tgram://bot/chat ntfy://ntfy.sh/sudo-alerts"
```

### Using a custom command

Any shell command works. The following environment variables are available:

| Variable | Example | Description |
|---|---|---|
| `NOTIFY_USERNAME` | `jordan` | User requesting sudo |
| `NOTIFY_HOSTNAME` | `web-prod-1` | Host where sudo was invoked |
| `NOTIFY_USER_CODE` | `ABCDEF-123456` | Challenge code |
| `NOTIFY_APPROVAL_URL` | `https://sudo.example.com/approve/ABCDEF-123456` | Clickable approval link |
| `NOTIFY_EXPIRES_IN` | `120` | Seconds until challenge expires |
| `NOTIFY_USER_URLS` | `tgram://bot/12345` | Per-user notification URL(s) from mapping file (empty if no mapping) |

Notification failures never block sudo — the challenge is created regardless, and the approval URL is always shown in the terminal.

Example with curl to ntfy:

```yaml
environment:
  PAM_POCKETID_NOTIFY_COMMAND: >-
    curl -s
    -H "Title: Sudo approval needed"
    -H "Click: $NOTIFY_APPROVAL_URL"
    -d "Sudo: $NOTIFY_USERNAME@$NOTIFY_HOSTNAME — Code: $NOTIFY_USER_CODE — $NOTIFY_APPROVAL_URL"
    ntfy.sh/my-sudo-alerts
  # The Click: header makes the notification clickable in ntfy mobile/desktop apps
```

### Per-user routing

By default, all notifications go to the same destination. To route notifications to individual users (e.g., each person gets their own Telegram message), create a JSON mapping file:

```json
{
  "hazely": "tgram://bot_token/hazely_chat_id",
  "sunny": "tgram://bot_token/sunny_chat_id ntfy://ntfy.sh/sunny-alerts",
  "*": "slack://token/channel/#ops-alerts"
}
```

- Each key is a username, mapped to one or more Apprise URLs (space-separated).
- `"*"` is the fallback for users without an explicit entry (optional but recommended).
- The file must be an absolute path, mode `0600`, and owned by root (it contains bot tokens).
- The file is re-read on each notification, so changes take effect without restarting the server.
- When adding new system users, remember to add their notification mapping. Users without a mapping (and no `"*"` fallback) will not receive push notifications.

Point the server at the file. The recommended pattern combines per-user URLs with a global ops channel, so unmapped users still generate an ops notification:

```yaml
environment:
  PAM_POCKETID_NOTIFY_USERS_FILE: /etc/pam-pocketid-notify-users.json
  PAM_POCKETID_NOTIFY_COMMAND: >-
    apprise -t "Sudo approval needed"
    -b "User: $NOTIFY_USERNAME\nHost: $NOTIFY_HOSTNAME\nCode: $NOTIFY_USER_CODE\nApprove: $NOTIFY_APPROVAL_URL\nExpires: ${NOTIFY_EXPIRES_IN}s"
    $NOTIFY_USER_URLS "$APPRISE_OPS_CHANNEL"
  PAM_POCKETID_NOTIFY_ENV: "APPRISE_"
```

For per-user only routing (no global ops channel), use a `"*"` wildcard in the JSON to ensure every user has a destination, or guard the command to skip when empty:

```yaml
  PAM_POCKETID_NOTIFY_COMMAND: >-
    [ -z "$NOTIFY_USER_URLS" ] && exit 0;
    apprise -t "Sudo approval needed"
    -b "User: $NOTIFY_USERNAME\nHost: $NOTIFY_HOSTNAME\nApprove: $NOTIFY_APPROVAL_URL"
    $NOTIFY_USER_URLS
```

The per-user URL(s) are passed as `NOTIFY_USER_URLS`. Do not quote `$NOTIFY_USER_URLS` in the command — when unquoted, shell word splitting correctly passes multiple space-separated URLs as separate arguments to apprise. Quoting it would pass the entire string as a single (invalid) URL.

### Limitations

- Notifications are best-effort with no retry on failure.
- Concurrency is limited to 10 simultaneous notification commands; excess notifications are skipped.
- Each notification command has a 15-second timeout.
- Per-user routing requires a JSON mapping file (see above); without it, all challenges go to the same destination.
- Failures are logged but never block the sudo challenge flow.
- If the user has multiple devices, all devices receiving the notification service will get the alert (routing is handled by the notification service, not pam-pocketid).

## Break-glass authentication

Break-glass is a fallback authentication mechanism that activates when the pam-pocketid server is unreachable. It allows sudo to proceed using a locally stored password, ensuring you are never locked out of your hosts.

### When it activates

Break-glass only activates on **network-level failures** — dial errors (connection refused, host unreachable) and DNS resolution failures. It does **not** activate on HTTP errors (e.g., 500 Internal Server Error) or request timeouts, because those indicate the server is reachable but having issues. This distinction prevents a malicious server from intentionally triggering break-glass fallback.

### Setup

Generate a break-glass password on each managed host:

```bash
pam-pocketid rotate-breakglass
```

This generates a password, stores a bcrypt hash at `/etc/pam-pocketid-breakglass`, and optionally escrows the plaintext to the server. If escrow is not configured, the password is printed to stdout — save it securely.

### Password types

| Type | Format | Entropy |
|---|---|---|
| `random` (default) | 32 random bytes, base64url-encoded (43 chars) | 256 bits |
| `passphrase` | 10 words joined with dashes (e.g., `calm-grip-hawk-note-surf-atom-bold-deer-flux-iron`) | 80 bits |
| `alphanumeric` | 24 unambiguous alphanumeric characters | ~138 bits |

Set via `PAM_POCKETID_BREAKGLASS_PASSWORD_TYPE` in `/etc/pam-pocketid.conf`.

### Rotation

Passwords are automatically rotated based on `PAM_POCKETID_BREAKGLASS_ROTATION_DAYS` (default 90 days). Rotation happens opportunistically during sudo sessions when the hash file's age exceeds the configured interval.

To force an immediate rotation:

```bash
pam-pocketid rotate-breakglass --force
```

The server can also signal all clients to rotate by setting `PAM_POCKETID_BREAKGLASS_ROTATE_BEFORE` to an RFC3339 timestamp. Clients with hash files older than this timestamp will rotate after their next successful authentication.

### Rate limiting

After 3 consecutive failed break-glass attempts, exponential backoff kicks in: 1s, 2s, 4s, ... up to a maximum of 300s. The failure counter is stored in `/var/run/pam-pocketid-breakglass-failures` (tmpfs, resets on reboot) and is cleared on successful authentication.

### Escrow

The server can escrow break-glass passwords to external systems (1Password, HashiCorp Vault, etc.) by configuring `PAM_POCKETID_ESCROW_COMMAND`. When a client rotates its password, the plaintext is sent to the server's `/api/breakglass/escrow` endpoint, which pipes it to the escrow command via stdin. The hostname is available as `BREAKGLASS_HOSTNAME`.

Each host can only escrow for its own hostname (verified via an HMAC-based per-host token).

### Verification

To test a break-glass password against the stored hash without triggering a sudo session:

```bash
pam-pocketid verify-breakglass
```

## CLI reference

| Command | Description |
|---|---|
| `pam-pocketid` | PAM helper (called by pam_exec, not run directly) |
| `pam-pocketid serve` | Run the authentication server |
| `pam-pocketid rotate-breakglass [--force]` | Rotate the break-glass password |
| `pam-pocketid verify-breakglass` | Verify a break-glass password against the stored hash |
| `pam-pocketid --help` | Show usage information |

## Monitoring

### Health check

`GET /healthz` returns `ok` with HTTP 200. Use this for load balancer or container health checks.

### Prometheus metrics

`GET /metrics` exposes metrics in Prometheus format. All metrics are prefixed with `pam_pocketid_`.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `challenges_created_total` | counter | | Total sudo challenges created |
| `challenges_approved_total` | counter | | Challenges approved via OIDC authentication |
| `challenges_auto_approved_total` | counter | | Challenges auto-approved via grace period |
| `challenges_denied_total` | counter | `reason` | Challenges denied (reasons: `oidc_error`, `nonce_mismatch`, `identity_mismatch`) |
| `challenges_expired_total` | counter | | Challenges that expired without resolution |
| `challenge_duration_seconds` | histogram | | Time from challenge creation to resolution |
| `rate_limit_rejections_total` | counter | | Challenge creation requests rejected by rate limiting |
| `auth_failures_total` | counter | | Requests rejected due to invalid shared secret |
| `active_challenges` | gauge | | Number of currently pending challenges |
| `breakglass_escrow_total` | counter | `status` | Break-glass escrow operations (status: `success`, `failure`) |
| `notifications_total` | counter | `status` | Push notification attempts (status: `sent`, `failed`, `skipped`) |

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
cat > /etc/pam-pocketid.conf <<EOF
PAM_POCKETID_SERVER_URL=https://sudo.example.com
PAM_POCKETID_SHARED_SECRET=your-shared-secret
EOF
chmod 600 /etc/pam-pocketid.conf

# Configure PAM for sudo (and sudo -i)
cat > /etc/pam.d/sudo <<EOF
auth    required    pam_exec.so    stdout /usr/local/bin/pam-pocketid
account required    pam_unix.so
session required    pam_limits.so
EOF
cp /etc/pam.d/sudo /etc/pam.d/sudo-i
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
- **Break-glass fallback** — Uses bcrypt (cost 12), rate limiting with exponential backoff, and timing-equalized responses to prevent timing oracles that distinguish "file error" from "wrong password"
- **HMAC-verified denial/expiry** — When a shared secret is configured, the PAM client ignores unverified status changes (denials, expirations), preventing MITM approval/denial injection
- **Terminal output sanitization** — Server responses displayed in the terminal are stripped of ANSI escapes, C1 control characters, bidirectional overrides, and zero-width characters
- **Config file security** — The config file is read with `O_NOFOLLOW` (no symlinks), must be mode 0600, and must be owned by root
- **Notification users file security** — The per-user notification mapping file (`PAM_POCKETID_NOTIFY_USERS_FILE`) uses the same hardening: `O_NOFOLLOW`, fd-based stat (no TOCTOU gap), mode 0600 enforced, root ownership enforced, and a 1MB size limit. The file is re-read on each notification to support hot-reloading
- **Grace period is per-username** — Approving sudo on one host grants the grace period on all hosts querying the same server (not scoped per-host)

### Disaster recovery

- **Server down** — Break-glass fallback activates automatically on network-level failures if a break-glass hash file exists on the host. Users are prompted for the break-glass password.
- **OIDC provider down** — Challenges can be created but not approved (the OIDC flow will fail). If the server itself becomes unreachable as a result, break-glass activates.
- **Server restart** — In-memory challenges are lost. Any in-flight sudo sessions that were polling will time out and fail. Users simply re-run their sudo command.
- **Break-glass password lost** — Re-run `pam-pocketid rotate-breakglass --force` on the affected host to generate a new password.

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
