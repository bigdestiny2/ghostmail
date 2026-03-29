#!/bin/bash
# GhostMail Tor Hidden Service Setup Script
# This script generates the torrc configuration needed to run
# GhostMail as a Tor hidden service.

set -e

GHOSTMAIL_SMTP_PORT="${GHOSTMAIL_SMTP_PORT:-25}"
GHOSTMAIL_IMAP_PORT="${GHOSTMAIL_IMAP_PORT:-993}"
GHOSTMAIL_HTTP_PORT="${GHOSTMAIL_HTTP_PORT:-8443}"
TOR_DATA_DIR="${TOR_DATA_DIR:-/var/lib/tor}"
HIDDEN_SERVICE_DIR="${TOR_DATA_DIR}/ghostmail"

echo "=== GhostMail Tor Hidden Service Setup ==="
echo ""
echo "This script outputs torrc configuration for GhostMail."
echo "Append this to your /etc/tor/torrc and restart Tor."
echo ""
echo "Local ports:"
echo "  SMTP: ${GHOSTMAIL_SMTP_PORT}"
echo "  IMAP: ${GHOSTMAIL_IMAP_PORT}"
echo "  HTTP: ${GHOSTMAIL_HTTP_PORT}"
echo ""
echo "--- Add to /etc/tor/torrc ---"
echo ""

cat <<EOF
# GhostMail Hidden Service
HiddenServiceDir ${HIDDEN_SERVICE_DIR}
HiddenServiceVersion 3
HiddenServicePort 25 127.0.0.1:${GHOSTMAIL_SMTP_PORT}
HiddenServicePort 993 127.0.0.1:${GHOSTMAIL_IMAP_PORT}
HiddenServicePort 443 127.0.0.1:${GHOSTMAIL_HTTP_PORT}

# Enable control port for GhostMail ephemeral service management (optional)
# Uncomment if using GhostMail's built-in Tor integration instead of manual torrc
# ControlPort 9051
# CookieAuthentication 1
EOF

echo ""
echo "--- End torrc ---"
echo ""
echo "After restarting Tor, your .onion address will be at:"
echo "  ${HIDDEN_SERVICE_DIR}/hostname"
echo ""
echo "IMPORTANT: Configure GhostMail to bind only to 127.0.0.1"
echo "when running as a Tor-only service."
echo ""
echo "Example ghostmail.toml for Tor-only mode:"
echo ""

cat <<'EOF'
[server]
hostname = "<your-onion-address>.onion"

[smtp]
listen_addr = "127.0.0.1:25"
submission_addr = "127.0.0.1:587"

[imap]
listen_addr = "127.0.0.1:993"

[admin]
listen_addr = "127.0.0.1:8443"

[tor]
enabled = true
control_addr = "127.0.0.1:9051"
auth_cookie_path = "/var/lib/tor/control_auth_cookie"
EOF
