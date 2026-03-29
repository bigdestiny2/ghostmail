#!/bin/sh
# GhostMail One-Click Installer
# Usage: curl -fsSL https://get.ghostmail.dev | sh
# Or:    curl -fsSL https://raw.githubusercontent.com/ghostmail/ghostmail/main/install.sh | sh
#
# Environment variables (all optional):
#   GHOSTMAIL_DOMAIN        Your email domain (prompted if not set)
#   GHOSTMAIL_ADMIN_USER    Admin username (default: admin)
#   GHOSTMAIL_ADMIN_PASSWORD Admin password (auto-generated if not set)
#   GHOSTMAIL_INSTALL_DIR   Install directory (default: ~/ghostmail)

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
err()   { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }

# --- Banner ---
printf "${BOLD}"
cat << 'BANNER'

   ____  _               _   __  __       _ _
  / ___|| |__   ___  ___| |_|  \/  | __ _(_) |
 | |  _ | '_ \ / _ \/ __| __| |\/| |/ _` | | |
 | |_| || | | | (_) \__ \ |_| |  | | (_| | | |
  \____||_| |_|\___/|___/\__|_|  |_|\__,_|_|_|

  Zero-Knowledge Encrypted Email Server

BANNER
printf "${NC}"

# --- Check prerequisites ---
info "Checking prerequisites..."

if ! command -v docker >/dev/null 2>&1; then
    err "Docker is not installed."
    echo ""
    echo "  Install Docker: https://docs.docker.com/get-docker/"
    echo ""
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    err "Docker daemon is not running. Please start Docker and try again."
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    err "Docker Compose v2 is required."
    echo ""
    echo "  Install Docker Compose: https://docs.docker.com/compose/install/"
    echo ""
    exit 1
fi

ok "Docker and Docker Compose found"

# --- Collect configuration ---
INSTALL_DIR="${GHOSTMAIL_INSTALL_DIR:-$HOME/ghostmail}"

if [ -z "$GHOSTMAIL_DOMAIN" ]; then
    printf "${BOLD}Enter your email domain${NC} (e.g., example.com): "
    read -r GHOSTMAIL_DOMAIN
    if [ -z "$GHOSTMAIL_DOMAIN" ]; then
        err "Domain is required."
        exit 1
    fi
fi

GHOSTMAIL_HOSTNAME="${GHOSTMAIL_HOSTNAME:-mail.$GHOSTMAIL_DOMAIN}"
GHOSTMAIL_ADMIN_USER="${GHOSTMAIL_ADMIN_USER:-admin}"

if [ -z "$GHOSTMAIL_ADMIN_PASSWORD" ]; then
    GHOSTMAIL_ADMIN_PASSWORD=$(openssl rand -base64 18 2>/dev/null || head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)
fi

info "Domain:    $GHOSTMAIL_DOMAIN"
info "Hostname:  $GHOSTMAIL_HOSTNAME"
info "Admin:     $GHOSTMAIL_ADMIN_USER@$GHOSTMAIL_DOMAIN"
info "Directory: $INSTALL_DIR"

# --- Check ports ---
PORTS_OK=true
for port in 25 587 993 80 443; do
    if (echo >/dev/tcp/localhost/$port) 2>/dev/null; then
        warn "Port $port is already in use"
        PORTS_OK=false
    fi
done

if [ "$PORTS_OK" = false ]; then
    warn "Some ports are in use. GhostMail may not start correctly."
    printf "Continue anyway? [y/N] "
    read -r REPLY
    case "$REPLY" in
        [yY]*) ;;
        *) echo "Aborted."; exit 1 ;;
    esac
fi

# --- Create directory structure ---
info "Creating deployment files..."
mkdir -p "$INSTALL_DIR/configs/caddy"

# --- Write .env ---
cat > "$INSTALL_DIR/.env" <<EOF
GHOSTMAIL_HOSTNAME=$GHOSTMAIL_HOSTNAME
GHOSTMAIL_DOMAIN=$GHOSTMAIL_DOMAIN
GHOSTMAIL_ADMIN_USER=$GHOSTMAIL_ADMIN_USER
GHOSTMAIL_ADMIN_PASSWORD=$GHOSTMAIL_ADMIN_PASSWORD
GHOSTMAIL_DATA_DIR=/var/lib/ghostmail
GHOSTMAIL_LOG_LEVEL=info
GHOSTMAIL_ADMIN_ADDR=:8080
CADDY_DOMAIN=$GHOSTMAIL_HOSTNAME
EOF

# --- Write docker-compose.yml ---
cat > "$INSTALL_DIR/docker-compose.yml" <<'EOF'
services:
  ghostmail:
    image: ghostmail/ghostmail:latest
    container_name: ghostmail
    restart: unless-stopped
    env_file: .env
    ports:
      - "25:25"
      - "587:587"
      - "993:993"
      - "8080:8080"
    volumes:
      - ghostmail-data:/var/lib/ghostmail
      - ghostmail-config:/etc/ghostmail
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

  caddy:
    image: caddy:2-alpine
    container_name: ghostmail-caddy
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./configs/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    env_file: .env
    depends_on:
      ghostmail:
        condition: service_healthy

volumes:
  ghostmail-data:
  ghostmail-config:
  caddy-data:
  caddy-config:
EOF

# --- Write Caddyfile ---
cat > "$INSTALL_DIR/configs/caddy/Caddyfile" <<'EOF'
{$CADDY_DOMAIN:localhost} {
	reverse_proxy ghostmail:8080
}
EOF

ok "Deployment files written"

# --- Deploy ---
info "Starting GhostMail..."
cd "$INSTALL_DIR"
docker compose pull --quiet 2>/dev/null || true
docker compose up -d

# --- Wait for health ---
info "Waiting for GhostMail to be ready..."
HEALTHY=false
for i in $(seq 1 30); do
    if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    sleep 2
done

if [ "$HEALTHY" = true ]; then
    ok "GhostMail is running!"
else
    warn "GhostMail hasn't passed health check yet. It may still be starting."
    echo "  Check logs: docker compose -f $INSTALL_DIR/docker-compose.yml logs ghostmail"
fi

# --- Get server IP ---
SERVER_IP=$(curl -4 -sf ifconfig.me 2>/dev/null || echo "<your-server-ip>")

# --- Print results ---
echo ""
printf "${BOLD}${GREEN}"
cat << 'DONE'
  ========================================
      GhostMail Deployment Complete!
  ========================================
DONE
printf "${NC}"
echo ""
printf "  ${BOLD}Admin Panel:${NC}  https://$GHOSTMAIL_HOSTNAME/admin/\n"
printf "  ${BOLD}Webmail:${NC}      https://$GHOSTMAIL_HOSTNAME/mail/\n"
printf "  ${BOLD}Login:${NC}        $GHOSTMAIL_ADMIN_USER@$GHOSTMAIL_DOMAIN\n"
printf "  ${BOLD}Password:${NC}     $GHOSTMAIL_ADMIN_PASSWORD\n"
echo ""
printf "  ${BOLD}${YELLOW}Save your password now — it won't be shown again.${NC}\n"
echo ""
printf "  ${BOLD}DNS Records to Add:${NC}\n"
echo ""
printf "  ${CYAN}%-8s %-30s %s${NC}\n" "TYPE" "NAME" "VALUE"
echo "  -------- ------------------------------ --------------------------------"
printf "  %-8s %-30s %s\n" "A" "mail.$GHOSTMAIL_DOMAIN" "$SERVER_IP"
printf "  %-8s %-30s %s\n" "MX" "$GHOSTMAIL_DOMAIN" "mail.$GHOSTMAIL_DOMAIN (pri 10)"
printf "  %-8s %-30s %s\n" "TXT" "$GHOSTMAIL_DOMAIN" "\"v=spf1 mx a -all\""
printf "  %-8s %-30s %s\n" "TXT" "_dmarc.$GHOSTMAIL_DOMAIN" "\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s\""
echo ""
echo "  For your DKIM record, run:"
echo "    docker exec ghostmail ghostctl dkim dns -domain $GHOSTMAIL_DOMAIN"
echo ""
echo "  Useful commands:"
echo "    Logs:      cd $INSTALL_DIR && docker compose logs -f"
echo "    Stop:      cd $INSTALL_DIR && docker compose down"
echo "    Update:    cd $INSTALL_DIR && docker compose pull && docker compose up -d"
echo ""
