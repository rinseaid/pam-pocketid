package main

import (
	"fmt"
	"net/http"
	"strings"
	"text/template"
)

// installScriptTmpl is a shell script template served at GET /install.sh.
// It pre-configures PAM_POCKETID_SERVER_URL from the server's ExternalURL so
// users can pipe the script directly: curl -fsSL {{.ServerURL}}/install.sh | sudo bash
//
// The shared secret is intentionally NOT embedded in the publicly-served script.
// Pass it at install time via the SHARED_SECRET env var for automated deployments:
//   SHARED_SECRET=xxx curl -fsSL {{.ServerURL}}/install.sh | sudo bash
const installScriptTmpl = `#!/bin/bash
set -euo pipefail

# pam-pocketid installer — pre-configured for {{.ServerURL}}
# Usage: curl -fsSL {{.ServerURL}}/install.sh | sudo bash
# Automated: SHARED_SECRET=xxx curl -fsSL {{.ServerURL}}/install.sh | sudo bash

REPO="rinseaid/pam-pocketid"
SERVER_URL="{{.ServerURL}}"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_FILE="/etc/pam-pocketid.conf"

# ── Preflight ───────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root (try: curl ... | sudo bash)" >&2
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    echo "Error: pam-pocketid only supports Linux" >&2
    exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SUFFIX="linux-amd64" ;;
    aarch64) SUFFIX="linux-arm64" ;;
    *)
        echo "Error: unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

# ── Binary ──────────────────────────────────────────────────────────────────

echo "Finding latest release..."
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest version" >&2
    exit 1
fi
echo "Latest version: $VERSION"

CURRENT="none"
if [ -f "$INSTALL_DIR/pam-pocketid" ]; then
    CURRENT=$("$INSTALL_DIR/pam-pocketid" --version 2>/dev/null || echo "unknown")
fi

if [ "$CURRENT" = "$VERSION" ]; then
    echo "Binary already at $VERSION — skipping download."
else
    BIN_URL="https://github.com/$REPO/releases/download/$VERSION/pam-pocketid-$SUFFIX"
    SUMS_URL="https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS"
    TMP_BIN=$(mktemp /tmp/pam-pocketid-XXXXXX)
    TMP_SUMS=$(mktemp /tmp/pam-pocketid-sums-XXXXXX)
    trap 'rm -f "$TMP_BIN" "$TMP_SUMS"' EXIT

    echo "Downloading $BIN_URL..."
    curl -fsSL -o "$TMP_BIN" "$BIN_URL"
    curl -fsSL -o "$TMP_SUMS" "$SUMS_URL"

    # Rename to expected filename for sha256sum check
    NAMED_TMP="/tmp/pam-pocketid-$SUFFIX"
    cp "$TMP_BIN" "$NAMED_TMP"
    trap 'rm -f "$TMP_BIN" "$TMP_SUMS" "$NAMED_TMP"' EXIT

    cd /tmp
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c --ignore-missing "$(basename "$TMP_SUMS")" 2>/dev/null \
            || { echo "ERROR: checksum mismatch — aborting" >&2; exit 1; }
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c --ignore-missing "$(basename "$TMP_SUMS")" 2>/dev/null \
            || { echo "ERROR: checksum mismatch — aborting" >&2; exit 1; }
    else
        echo "WARNING: no sha256sum available — skipping checksum verification"
    fi

    install -m 755 "$NAMED_TMP" "$INSTALL_DIR/pam-pocketid"
    echo "Installed pam-pocketid $VERSION"
fi

# ── Config file ─────────────────────────────────────────────────────────────

if [ -f "$CONFIG_FILE" ]; then
    conf_url=$(grep -E '^PAM_POCKETID_SERVER_URL=' "$CONFIG_FILE" | cut -d= -f2- || true)
    conf_secret=$(grep -E '^PAM_POCKETID_SHARED_SECRET=' "$CONFIG_FILE" | cut -d= -f2- || true)
    echo "Config file exists: $CONFIG_FILE"
    if [ -z "$conf_url" ]; then
        echo "  WARNING: PAM_POCKETID_SERVER_URL missing"
    else
        echo "  PAM_POCKETID_SERVER_URL=$conf_url"
    fi
    if [ -z "$conf_secret" ]; then
        echo "  WARNING: PAM_POCKETID_SHARED_SECRET missing"
    else
        echo "  PAM_POCKETID_SHARED_SECRET=${conf_secret:0:4}****"
    fi
    # Overwrite if SHARED_SECRET provided and config differs
    NEW_SECRET="${SHARED_SECRET:-}"
    if [ -n "$NEW_SECRET" ] && { [ "$conf_url" != "$SERVER_URL" ] || [ "$conf_secret" != "$NEW_SECRET" ]; }; then
        cat > "$CONFIG_FILE" <<EOF
PAM_POCKETID_SERVER_URL=$SERVER_URL
PAM_POCKETID_SHARED_SECRET=$NEW_SECRET
EOF
        chmod 600 "$CONFIG_FILE"
        echo "  Updated $CONFIG_FILE with current values."
    else
        echo "  Config is up to date."
    fi
    CONFIG_WRITTEN=1
else
    SECRET="${SHARED_SECRET:-}"
    if [ -z "$SECRET" ]; then
        if [ -t 0 ]; then
            # Interactive: prompt securely
            read -rsp "Enter PAM_POCKETID_SHARED_SECRET: " SECRET
            echo
        else
            echo ""
            echo "NOTE: SHARED_SECRET not set and stdin is not a terminal."
            echo "Create $CONFIG_FILE manually after this script completes:"
            echo ""
            echo "  cat > $CONFIG_FILE <<'EOF'"
            echo "  PAM_POCKETID_SERVER_URL=$SERVER_URL"
            echo "  PAM_POCKETID_SHARED_SECRET=<your-shared-secret>"
            echo "  EOF"
            echo "  chmod 600 $CONFIG_FILE"
        fi
    fi
    if [ -n "$SECRET" ]; then
        cat > "$CONFIG_FILE" <<EOF
PAM_POCKETID_SERVER_URL=$SERVER_URL
PAM_POCKETID_SHARED_SECRET=$SECRET
EOF
        chmod 600 "$CONFIG_FILE"
        echo "Created $CONFIG_FILE"
        CONFIG_WRITTEN=1
    else
        CONFIG_WRITTEN=0
    fi
fi

# ── Systemd rotation timer ───────────────────────────────────────────────────

if command -v systemctl >/dev/null 2>&1; then
    for UNIT in pam-pocketid-rotate.service pam-pocketid-rotate.timer; do
        curl -fsSL -o "$SYSTEMD_DIR/$UNIT" \
            "https://raw.githubusercontent.com/$REPO/$VERSION/systemd/$UNIT"
    done
    systemctl daemon-reload
    systemctl enable --now pam-pocketid-rotate.timer
    echo "Enabled weekly break-glass rotation timer"
else
    echo "Warning: systemd not found — set up a weekly cron job for rotation:"
    echo "  0 3 * * 0 root /usr/local/bin/pam-pocketid rotate-breakglass"
fi

# ── PAM configuration ────────────────────────────────────────────────────────

PAM_LINE='auth    required    pam_exec.so    stdout /usr/local/bin/pam-pocketid'

for PAM_FILE in /etc/pam.d/sudo /etc/pam.d/sudo-i; do
    [ -f "$PAM_FILE" ] || continue
    if grep -q "pam-pocketid" "$PAM_FILE" 2>/dev/null; then
        echo "PAM already configured: $PAM_FILE"
        continue
    fi
    cp "$PAM_FILE" "${PAM_FILE}.bak"
    # Insert before the first auth or @include line
    awk -v line="$PAM_LINE" '
        !done && /^(auth[[:space:]]|@include)/ { print line; done=1 }
        { print }
    ' "${PAM_FILE}.bak" > "$PAM_FILE"
    echo "Updated $PAM_FILE (original saved as ${PAM_FILE}.bak)"
done

# ── Initial break-glass password ─────────────────────────────────────────────

if [ ! -f /etc/pam-pocketid-breakglass ]; then
    if [ "${CONFIG_WRITTEN:-0}" = "1" ]; then
        echo ""
        echo "Generating initial break-glass password..."
        if "$INSTALL_DIR/pam-pocketid" rotate-breakglass; then
            echo "Break-glass password configured."
        else
            echo "WARNING: break-glass setup failed — run manually:"
            echo "  sudo pam-pocketid rotate-breakglass"
        fi
    else
        echo ""
        echo "Skipping break-glass setup (no config file yet)."
        echo "Run after creating $CONFIG_FILE:"
        echo "  sudo pam-pocketid rotate-breakglass"
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "Done! pam-pocketid $VERSION installed."
if [ "${CONFIG_WRITTEN:-0}" != "1" ]; then
    echo "Remember to create $CONFIG_FILE and run: sudo pam-pocketid rotate-breakglass"
fi
`

// handleInstallScript serves a pre-configured shell installer script.
// GET /install.sh
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tmpl, err := template.New("install").Parse(installScriptTmpl)
	if err != nil {
		// Template is a compile-time constant; any parse error is a programmer bug.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := struct {
		ServerURL string
	}{
		ServerURL: strings.TrimRight(s.cfg.ExternalURL, "/"),
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=install.sh")
	// Prevent browsers from caching a stale version of the script.
	w.Header().Set("Cache-Control", "no-store")

	if err := tmpl.Execute(w, data); err != nil {
		// Can't write headers at this point; just log.
		fmt.Printf("ERROR: install script template: %v\n", err)
	}
}
