#!/bin/bash
# GhostMail macOS Installer
#
# Installs GhostMail as a native launchd service on macOS.
# Designed for Mac Mini self-hosting — no Docker required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ghostmail/ghostmail/main/deploy/macos/install-macos.sh | bash
#
# Or with options:
#   GHOSTMAIL_DOMAIN=example.com bash install-macos.sh

set -e

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { printf "${CYAN}[INFO]${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}[OK]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
err()   { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; exit 1; }

# --- Banner ---
printf "${BOLD}"
cat << 'BANNER'

   ____  _               _   __  __       _ _
  / ___|| |__   ___  ___| |_|  \/  | __ _(_) |
 | |  _ | '_ \ / _ \/ __| __| |\/| |/ _` | | |
 | |_| || | | | (_) \__ \ |_| |  | | (_| | | |
  \____||_| |_|\___/|___/\__|_|  |_|\__,_|_|_|

  macOS Native Installer

BANNER
printf "${NC}"

# --- Check platform ---
if [ "$(uname)" != "Darwin" ]; then
    err "This installer is for macOS only. Use install.sh for Linux/Docker."
fi

ARCH=$(uname -m)
case "$ARCH" in
    arm64) BINARY_SUFFIX="darwin-arm64" ;;
    x86_64) BINARY_SUFFIX="darwin-amd64" ;;
    *) err "Unsupported architecture: $ARCH" ;;
esac

info "Detected: macOS $ARCH"

# --- Configuration ---
INSTALL_DIR="/usr/local/ghostmail"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/usr/local/etc/ghostmail"
DATA_DIR="/usr/local/var/ghostmail"
LOG_DIR="/usr/local/var/log/ghostmail"
PLIST_NAME="com.ghostmail.server"
PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME.plist"

# --- Collect domain ---
if [ -z "$GHOSTMAIL_DOMAIN" ]; then
    printf "${BOLD}Enter your email domain${NC} (e.g., example.com): "
    read -r GHOSTMAIL_DOMAIN
    [ -z "$GHOSTMAIL_DOMAIN" ] && err "Domain is required."
fi

GHOSTMAIL_HOSTNAME="${GHOSTMAIL_HOSTNAME:-mail.$GHOSTMAIL_DOMAIN}"
GHOSTMAIL_ADMIN_USER="${GHOSTMAIL_ADMIN_USER:-admin}"

if [ -z "$GHOSTMAIL_ADMIN_PASSWORD" ]; then
    GHOSTMAIL_ADMIN_PASSWORD=$(openssl rand -base64 18)
fi

# --- Check for existing installation ---
if [ -f "$BIN_DIR/ghostmail" ]; then
    warn "GhostMail is already installed at $BIN_DIR/ghostmail"
    printf "Upgrade? [y/N] "
    read -r REPLY
    case "$REPLY" in
        [yY]*) info "Upgrading..." ;;
        *) echo "Aborted."; exit 0 ;;
    esac
fi

# --- Download or build ---
GITHUB_REPO="ghostmail/ghostmail"
LATEST_TAG=$(curl -sf "https://api.github.com/repos/$GITHUB_REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || echo "")

if [ -n "$LATEST_TAG" ]; then
    info "Downloading GhostMail $LATEST_TAG for $BINARY_SUFFIX..."
    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/download/$LATEST_TAG"

    TMPDIR=$(mktemp -d)
    curl -fsSL "$DOWNLOAD_URL/ghostmail-$BINARY_SUFFIX" -o "$TMPDIR/ghostmail" || err "Failed to download ghostmail binary"
    curl -fsSL "$DOWNLOAD_URL/ghostctl-$BINARY_SUFFIX" -o "$TMPDIR/ghostctl" || err "Failed to download ghostctl binary"
    chmod +x "$TMPDIR/ghostmail" "$TMPDIR/ghostctl"
else
    warn "No release found. Checking for local build..."
    if [ -f "./bin/ghostmail" ] && [ -f "./bin/ghostctl" ]; then
        TMPDIR=$(mktemp -d)
        cp ./bin/ghostmail ./bin/ghostctl "$TMPDIR/"
        info "Using local build"
    else
        # Try building from source
        if command -v go >/dev/null 2>&1; then
            info "Building from source..."
            TMPDIR=$(mktemp -d)
            if [ -f "go.mod" ]; then
                make build
                cp ./bin/ghostmail ./bin/ghostctl "$TMPDIR/"
            else
                err "Not in GhostMail source directory and no release available. Clone the repo first."
            fi
        else
            err "No release available and Go is not installed. Install Go or download a release."
        fi
    fi
fi

ok "Binaries ready"

# --- Install binaries ---
info "Installing binaries..."
sudo mkdir -p "$BIN_DIR"
sudo cp "$TMPDIR/ghostmail" "$BIN_DIR/ghostmail"
sudo cp "$TMPDIR/ghostctl" "$BIN_DIR/ghostctl"
sudo chmod +x "$BIN_DIR/ghostmail" "$BIN_DIR/ghostctl"
rm -rf "$TMPDIR"

ok "Installed ghostmail and ghostctl to $BIN_DIR"

# --- Create directories ---
info "Creating directories..."
sudo mkdir -p "$CONFIG_DIR/tls" "$DATA_DIR" "$LOG_DIR"
sudo chown -R "$(whoami)" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

# --- Write config ---
if [ ! -f "$CONFIG_DIR/ghostmail.toml" ]; then
    info "Writing configuration..."
    cat > "$CONFIG_DIR/ghostmail.toml" <<EOF
[server]
hostname = "$GHOSTMAIL_HOSTNAME"
data_dir = "$DATA_DIR"
log_level = "info"

[smtp]
listen_addr = ":25"
submission_addr = ":587"
max_message_size = 26214400
max_recipients = 100
require_tls = false
greeting = "GhostMail ESMTP"

[smtp.outbound]
enabled = true
max_retries = 8
retry_base_delay = "1m"
dead_letter_after = "48h"
concurrent_deliveries = 4

[imap]
listen_addr = ":993"
idle_timeout = "30m"
max_connections = 100

[crypto]
argon2_time = 3
argon2_memory = 65536
argon2_threads = 4
session_key_ttl = "30m"

[admin]
enabled = true
listen_addr = ":8080"

[webmail]
enabled = true

[aliases]
enabled = true
max_per_user = 50
default_domain = "$GHOSTMAIL_DOMAIN"

[expiry]
trash_ttl = "30d"
spam_ttl = "7d"
sweep_interval = "5m"
vacuum_interval = "24h"

[privacy]
strip_received_headers = true
strip_user_agent = true
strip_x_originating_ip = true
normalize_message_id = true
log_ips = false

[dkim]
selector = "ghostmail"
key_bits = 2048
EOF
    ok "Config written to $CONFIG_DIR/ghostmail.toml"
else
    warn "Config already exists, skipping"
fi

# --- Initial setup (domain + admin user) ---
export GHOSTMAIL_DATA_DIR="$DATA_DIR"

info "Setting up domain and admin account..."
"$BIN_DIR/ghostctl" domain add -name "$GHOSTMAIL_DOMAIN" -primary 2>/dev/null || true
"$BIN_DIR/ghostctl" user create \
    -username "$GHOSTMAIL_ADMIN_USER" \
    -domain "$GHOSTMAIL_DOMAIN" \
    -password "$GHOSTMAIL_ADMIN_PASSWORD" \
    -admin 2>/dev/null || true
"$BIN_DIR/ghostctl" dkim generate -domain "$GHOSTMAIL_DOMAIN" 2>/dev/null || true

ok "Domain and admin account created"

# --- Create launchd plist ---
info "Installing launchd service..."
mkdir -p "$HOME/Library/LaunchAgents"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_NAME</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN_DIR/ghostmail</string>
        <string>-config</string>
        <string>$CONFIG_DIR/ghostmail.toml</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>GHOSTMAIL_DATA_DIR</key>
        <string>$DATA_DIR</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/ghostmail.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/ghostmail.err</string>
    <key>WorkingDirectory</key>
    <string>$DATA_DIR</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>4096</integer>
    </dict>
</dict>
</plist>
EOF

# --- Start service ---
launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load "$PLIST_PATH"

ok "GhostMail service installed and started"

# --- Wait for health ---
info "Waiting for GhostMail to start..."
HEALTHY=false
for i in $(seq 1 15); do
    if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    sleep 2
done

if [ "$HEALTHY" = true ]; then
    ok "GhostMail is running!"
else
    warn "GhostMail may still be starting. Check logs: tail -f $LOG_DIR/ghostmail.log"
fi

# --- Get IP ---
SERVER_IP=$(curl -4 -sf ifconfig.me 2>/dev/null || echo "<your-server-ip>")

# --- Print results ---
echo ""
printf "${BOLD}${GREEN}"
cat << 'DONE'
  ========================================
    GhostMail macOS Install Complete!
  ========================================
DONE
printf "${NC}"
echo ""
printf "  ${BOLD}Admin Panel:${NC}  http://localhost:8080/admin/\n"
printf "  ${BOLD}Webmail:${NC}      http://localhost:8080/mail/\n"
printf "  ${BOLD}Login:${NC}        $GHOSTMAIL_ADMIN_USER@$GHOSTMAIL_DOMAIN\n"
printf "  ${BOLD}Password:${NC}     $GHOSTMAIL_ADMIN_PASSWORD\n"
echo ""
printf "  ${BOLD}${YELLOW}Save your password now!${NC}\n"
echo ""
printf "  ${BOLD}Paths:${NC}\n"
printf "    Config:  $CONFIG_DIR/ghostmail.toml\n"
printf "    Data:    $DATA_DIR\n"
printf "    Logs:    $LOG_DIR/ghostmail.log\n"
echo ""
printf "  ${BOLD}Service commands:${NC}\n"
printf "    Stop:    launchctl unload ~/Library/LaunchAgents/$PLIST_NAME.plist\n"
printf "    Start:   launchctl load ~/Library/LaunchAgents/$PLIST_NAME.plist\n"
printf "    Logs:    tail -f $LOG_DIR/ghostmail.log\n"
echo ""
printf "  ${BOLD}DNS Records:${NC}\n"
echo ""
printf "  ${CYAN}%-8s %-30s %s${NC}\n" "TYPE" "NAME" "VALUE"
echo "  -------- ------------------------------ --------------------------------"
printf "  %-8s %-30s %s\n" "A" "mail.$GHOSTMAIL_DOMAIN" "$SERVER_IP"
printf "  %-8s %-30s %s\n" "MX" "$GHOSTMAIL_DOMAIN" "mail.$GHOSTMAIL_DOMAIN (pri 10)"
printf "  %-8s %-30s %s\n" "TXT" "$GHOSTMAIL_DOMAIN" "\"v=spf1 mx a -all\""
printf "  %-8s %-30s %s\n" "TXT" "_dmarc.$GHOSTMAIL_DOMAIN" "\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s\""
echo ""
echo "  For DKIM: ghostctl dkim dns -domain $GHOSTMAIL_DOMAIN"
echo ""
printf "  ${BOLD}For TLS (recommended):${NC}\n"
echo "    Install Caddy: brew install caddy"
echo "    Reverse proxy: caddy reverse-proxy --from mail.$GHOSTMAIL_DOMAIN --to localhost:8080"
echo ""
