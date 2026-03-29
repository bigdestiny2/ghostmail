#!/bin/bash
# GhostMail macOS Uninstaller
set -e

PLIST_NAME="com.ghostmail.server"
PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME.plist"

echo "GhostMail macOS Uninstaller"
echo ""

# Stop service
if launchctl list | grep -q "$PLIST_NAME"; then
    echo "Stopping GhostMail service..."
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
fi

echo ""
echo "This will remove:"
echo "  - Binaries:  /usr/local/bin/ghostmail, /usr/local/bin/ghostctl"
echo "  - Config:    /usr/local/etc/ghostmail/"
echo "  - Logs:      /usr/local/var/log/ghostmail/"
echo "  - Service:   $PLIST_PATH"
echo ""
echo "Data directory /usr/local/var/ghostmail/ will NOT be removed."
echo "Delete it manually if you want to remove all email data."
echo ""
printf "Continue? [y/N] "
read -r REPLY
case "$REPLY" in
    [yY]*) ;;
    *) echo "Aborted."; exit 0 ;;
esac

# Remove files
sudo rm -f /usr/local/bin/ghostmail /usr/local/bin/ghostctl
rm -f "$PLIST_PATH"
sudo rm -rf /usr/local/etc/ghostmail
sudo rm -rf /usr/local/var/log/ghostmail

echo ""
echo "GhostMail has been uninstalled."
echo "Email data is preserved at /usr/local/var/ghostmail/"
echo "To remove all data: sudo rm -rf /usr/local/var/ghostmail"
