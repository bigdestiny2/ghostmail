#!/bin/sh
set -e

CONFIG_FILE="/etc/ghostmail/ghostmail.toml"
DATA_DIR="${GHOSTMAIL_DATA_DIR:-/var/lib/ghostmail}"
DOMAIN="${GHOSTMAIL_DOMAIN:-example.com}"
HOSTNAME="${GHOSTMAIL_HOSTNAME:-mail.$DOMAIN}"
ADMIN_USER="${GHOSTMAIL_ADMIN_USER:-admin}"
ADMIN_PASS="${GHOSTMAIL_ADMIN_PASSWORD:-$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)}"
ADMIN_ADDR="${GHOSTMAIL_ADMIN_ADDR:-:8080}"
LOG_LEVEL="${GHOSTMAIL_LOG_LEVEL:-info}"

# Generate config if it doesn't exist
if [ ! -f "$CONFIG_FILE" ]; then
    echo "==> Generating GhostMail configuration..."
    cat > "$CONFIG_FILE" <<EOF
[server]
hostname = "$HOSTNAME"
data_dir = "$DATA_DIR"
log_level = "$LOG_LEVEL"

[smtp]
listen_addr = ":25"
submission_addr = ":587"
max_message_size = 26214400
max_recipients = 100
require_tls = true
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
listen_addr = "$ADMIN_ADDR"

[webmail]
enabled = true

[aliases]
enabled = true
max_per_user = 50
default_domain = "$DOMAIN"

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
    echo "==> Config written to $CONFIG_FILE"
fi

# ghostctl uses GHOSTMAIL_DATA_DIR env var, not -config flag
export GHOSTMAIL_DATA_DIR="$DATA_DIR"

# Auto-setup: create domain and admin user if no users exist
USER_COUNT=$(ghostctl user list 2>/dev/null | grep -c "@" || echo "0")

if [ "$USER_COUNT" = "0" ]; then
    echo "==> First boot detected. Running auto-setup..."

    # Create primary domain
    echo "==> Creating domain: $DOMAIN"
    ghostctl domain add -name "$DOMAIN" -primary 2>/dev/null || true

    # Create admin user
    echo "==> Creating admin user: $ADMIN_USER@$DOMAIN"
    ghostctl user create \
        -username "$ADMIN_USER" \
        -domain "$DOMAIN" \
        -password "$ADMIN_PASS" \
        -admin 2>/dev/null || true

    # Generate DKIM keys
    echo "==> Generating DKIM keys..."
    ghostctl dkim generate -domain "$DOMAIN" 2>/dev/null || true

    echo ""
    echo "========================================"
    echo "  GhostMail Auto-Setup Complete"
    echo "========================================"
    echo ""
    echo "  Admin login: $ADMIN_USER@$DOMAIN"
    echo "  Admin panel: https://your-server/admin/"
    echo "  Webmail:     https://your-server/mail/"
    echo ""
    echo "  Add these DNS records for your domain:"
    echo ""
    echo "  MX:    $DOMAIN  ->  $HOSTNAME  (priority 10)"
    echo "  SPF:   $DOMAIN  IN TXT \"v=spf1 mx a -all\""
    echo "  DMARC: _dmarc.$DOMAIN IN TXT \"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s\""
    echo ""
    ghostctl dkim dns -domain "$DOMAIN" 2>/dev/null || echo "  (Run 'ghostctl dkim dns' for DKIM record)"
    echo ""
    echo "========================================"
    echo ""
fi

# Start GhostMail
exec ghostmail -config "$CONFIG_FILE"
