#!/bin/bash
# GhostMail Installation Script
# Installs GhostMail binaries, creates system user, and sets up directories.

set -e

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="/etc/ghostmail"
DATA_DIR="/var/lib/ghostmail"
BIN_DIR="${PREFIX}/bin"

echo "=== GhostMail Installer ==="
echo ""

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# Create system user
if ! id -u ghostmail &>/dev/null; then
    echo "Creating ghostmail system user..."
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin --create-home ghostmail
fi

# Create directories
echo "Creating directories..."
mkdir -p "$CONFIG_DIR/tls"
mkdir -p "$DATA_DIR"

# Install binaries
if [ -f "bin/ghostmail" ] && [ -f "bin/ghostctl" ]; then
    echo "Installing binaries..."
    install -m 755 bin/ghostmail "$BIN_DIR/ghostmail"
    install -m 755 bin/ghostctl "$BIN_DIR/ghostctl"
else
    echo "Error: Binaries not found. Run 'make build' first."
    exit 1
fi

# Install config
if [ ! -f "$CONFIG_DIR/ghostmail.toml" ]; then
    echo "Installing default configuration..."
    install -m 640 -g ghostmail configs/ghostmail.example.toml "$CONFIG_DIR/ghostmail.toml"
else
    echo "Configuration exists, not overwriting."
fi

# Install systemd service
if [ -d /etc/systemd/system ]; then
    echo "Installing systemd service..."
    install -m 644 scripts/ghostmail.service /etc/systemd/system/ghostmail.service
    systemctl daemon-reload
fi

# Set permissions
chown -R ghostmail:ghostmail "$DATA_DIR"
chown -R root:ghostmail "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit /etc/ghostmail/ghostmail.toml with your settings"
echo "  2. Add TLS certificates to /etc/ghostmail/tls/"
echo "  3. Create your first domain and admin user:"
echo "     ghostctl domain add -name mail.example.com -primary"
echo "     ghostctl user create -username admin -domain mail.example.com -password 'your-secure-password' -admin"
echo "  4. Generate DKIM keys:"
echo "     ghostctl dkim generate -domain mail.example.com"
echo "  5. Start the service:"
echo "     systemctl enable --now ghostmail"
echo "  6. Access admin panel at https://your-server:8443/admin/"
echo ""
