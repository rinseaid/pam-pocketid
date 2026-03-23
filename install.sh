#!/bin/bash
set -euo pipefail

# pam-pocketid installer for Linux (amd64/arm64)
# Usage: curl -fsSL https://raw.githubusercontent.com/rinseaid/pam-pocketid/main/install.sh | sudo bash
#
# What it does:
#   1. Downloads the latest pam-pocketid binary from GitHub releases
#   2. Installs it to /usr/local/bin/pam-pocketid
#   3. Installs the systemd timer for weekly break-glass rotation
#   4. Prints next steps (config file + PAM setup)

REPO="rinseaid/pam-pocketid"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

# Require root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (try: sudo bash)" >&2
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SUFFIX="linux-amd64" ;;
    aarch64) SUFFIX="linux-arm64" ;;
    *)
        echo "Error: unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

# Get latest version
echo "Finding latest release..."
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest version" >&2
    exit 1
fi
echo "Latest version: $VERSION"

# Check if already installed at this version
if [ -f "$INSTALL_DIR/pam-pocketid" ]; then
    CURRENT=$("$INSTALL_DIR/pam-pocketid" --version 2>/dev/null || echo "unknown")
    if [ "$CURRENT" = "$VERSION" ]; then
        echo "Already at $VERSION — nothing to do."
        exit 0
    fi
    echo "Upgrading from $CURRENT to $VERSION"
else
    echo "Installing $VERSION"
fi

# Download
URL="https://github.com/$REPO/releases/download/$VERSION/pam-pocketid-$SUFFIX"
echo "Downloading $URL..."
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
curl -fsSL -o "$TMP" "$URL"

# Install binary
install -m 755 "$TMP" "$INSTALL_DIR/pam-pocketid"
echo "Installed $INSTALL_DIR/pam-pocketid ($VERSION)"

# Install systemd timer (if systemd is available)
if command -v systemctl >/dev/null 2>&1; then
    SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
    # Try local files first (running from repo), then download
    if [ -f "$SCRIPT_DIR/systemd/pam-pocketid-rotate.service" ]; then
        cp "$SCRIPT_DIR/systemd/pam-pocketid-rotate.service" "$SYSTEMD_DIR/"
        cp "$SCRIPT_DIR/systemd/pam-pocketid-rotate.timer" "$SYSTEMD_DIR/"
    else
        curl -fsSL -o "$SYSTEMD_DIR/pam-pocketid-rotate.service" \
            "https://raw.githubusercontent.com/$REPO/$VERSION/systemd/pam-pocketid-rotate.service"
        curl -fsSL -o "$SYSTEMD_DIR/pam-pocketid-rotate.timer" \
            "https://raw.githubusercontent.com/$REPO/$VERSION/systemd/pam-pocketid-rotate.timer"
    fi
    systemctl daemon-reload
    systemctl enable --now pam-pocketid-rotate.timer
    echo "Enabled weekly break-glass rotation timer"
else
    echo "Warning: systemd not found — skipping rotation timer"
    echo "  Set up a weekly cron job: 0 3 * * 0 root /usr/local/bin/pam-pocketid rotate-breakglass"
fi

# Check for config file
if [ ! -f /etc/pam-pocketid.conf ]; then
    echo ""
    echo "Next steps:"
    echo "  1. Create /etc/pam-pocketid.conf:"
    echo ""
    echo "     cat > /etc/pam-pocketid.conf <<EOF"
    echo "     PAM_POCKETID_SERVER_URL=https://your-server.example.com"
    echo "     PAM_POCKETID_SHARED_SECRET=your-shared-secret-here"
    echo "     EOF"
    echo "     chmod 600 /etc/pam-pocketid.conf"
    echo ""
    echo "  2. Configure PAM (/etc/pam.d/sudo):"
    echo ""
    echo "     auth required pam_exec.so stdout /usr/local/bin/pam-pocketid"
    echo ""
    echo "  See https://github.com/$REPO#readme for full documentation."
else
    echo "Config file exists: /etc/pam-pocketid.conf"
fi

echo ""
echo "Done! pam-pocketid $VERSION installed."
