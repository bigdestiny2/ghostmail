---
name: ghostmail-deploy
description: "Deploy GhostMail, a private zero-knowledge encrypted email server, using Docker Compose. Handles domain setup, TLS, admin account creation, and DNS record generation."
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - docker
        - curl
    emoji: "\U0001F4E7"
    homepage: "https://github.com/ghostmail/ghostmail"
---

# GhostMail Deploy

Deploy a private, zero-knowledge encrypted email server in one command.

## What This Skill Does

When the user asks to deploy an email server, set up GhostMail, or get a private mailbox, this skill:

1. Collects the user's domain name
2. Generates secure credentials
3. Deploys GhostMail via Docker Compose
4. Returns login details and required DNS records

## Trigger Phrases

- "Deploy my email server"
- "Set up GhostMail"
- "I need a private email server for mydomain.com"
- "Deploy encrypted email"
- "Set up self-hosted email"

## Required Information

Before deploying, you MUST collect:

- **Domain name** (e.g., `example.com`) — ask if not provided
- **Hostname** (defaults to `mail.<domain>`)
- **Admin username** (defaults to `admin`)
- **Admin password** — generate a strong 24-character random password if not provided. Use: `openssl rand -base64 18`

## Deployment Steps

### Step 1: Check Prerequisites

```bash
# Verify Docker is running
docker info > /dev/null 2>&1 || echo "ERROR: Docker is not running. Please start Docker first."

# Check port availability
for port in 25 587 993 80 443 8080; do
  (echo >/dev/tcp/localhost/$port) 2>/dev/null && echo "WARNING: Port $port is already in use" || true
done
```

If ports 25, 587, or 993 are in use, warn the user that another mail server may be running.

### Step 2: Create Deployment Directory

```bash
DEPLOY_DIR="$HOME/ghostmail"
mkdir -p "$DEPLOY_DIR/configs/caddy"
cd "$DEPLOY_DIR"
```

### Step 3: Write Environment File

Write the `.env` file using the collected information:

```bash
cat > "$DEPLOY_DIR/.env" <<'ENVEOF'
GHOSTMAIL_HOSTNAME=mail.DOMAIN_PLACEHOLDER
GHOSTMAIL_DOMAIN=DOMAIN_PLACEHOLDER
GHOSTMAIL_ADMIN_USER=ADMIN_USER_PLACEHOLDER
GHOSTMAIL_ADMIN_PASSWORD=ADMIN_PASS_PLACEHOLDER
GHOSTMAIL_DATA_DIR=/var/lib/ghostmail
GHOSTMAIL_LOG_LEVEL=info
GHOSTMAIL_ADMIN_ADDR=:8080
CADDY_DOMAIN=mail.DOMAIN_PLACEHOLDER
ENVEOF
```

Replace all `*_PLACEHOLDER` values with the actual collected values.

### Step 4: Write Docker Compose File

```bash
cat > "$DEPLOY_DIR/docker-compose.yml" <<'COMPOSEEOF'
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
COMPOSEEOF
```

### Step 5: Write Caddyfile

```bash
cat > "$DEPLOY_DIR/configs/caddy/Caddyfile" <<'CADDYEOF'
{$CADDY_DOMAIN:localhost} {
	reverse_proxy ghostmail:8080
}
CADDYEOF
```

### Step 6: Deploy

```bash
cd "$DEPLOY_DIR"
docker compose pull 2>/dev/null || true
docker compose up -d
```

### Step 7: Wait for Health Check

```bash
echo "Waiting for GhostMail to start..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo "GhostMail is healthy!"
    break
  fi
  sleep 2
done

# Verify
curl -s http://localhost:8080/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:8080/health
```

### Step 8: Report Results

After successful deployment, present the user with:

```
GhostMail is running!

Admin Panel:  https://mail.<domain>/admin/
Webmail:      https://mail.<domain>/mail/
Login:        <admin_user>@<domain>
Password:     <generated_password>

Add these DNS records to your domain registrar:

TYPE    NAME                    VALUE                           PRIORITY
----    ----                    -----                           --------
A       mail.<domain>           <server-ip>                     -
MX      <domain>                mail.<domain>                   10
TXT     <domain>                "v=spf1 mx a -all"             -
TXT     _dmarc.<domain>         "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"  -

Run this command to get your DKIM record:
  docker exec ghostmail ghostctl dkim dns -domain <domain>
```

If the user's server IP is unknown, instruct them to use `curl -4 ifconfig.me` to find it.

## Troubleshooting

If deployment fails, check:

```bash
# View logs
docker compose -f ~/ghostmail/docker-compose.yml logs ghostmail

# Check if containers are running
docker compose -f ~/ghostmail/docker-compose.yml ps

# Restart
docker compose -f ~/ghostmail/docker-compose.yml restart
```

## Updating GhostMail

```bash
cd ~/ghostmail
docker compose pull
docker compose up -d
```

## Uninstalling

```bash
cd ~/ghostmail
docker compose down -v  # -v removes volumes (deletes all email data!)
rm -rf ~/ghostmail
```

IMPORTANT: Warn the user that `docker compose down -v` permanently deletes all emails and encryption keys.

## Option A: Auto-DNS Configuration

If the user has their domain on a supported DNS provider (Cloudflare, DigitalOcean), you can auto-configure all DNS records — zero manual steps.

### Detect DNS Provider

```bash
# Detect which DNS provider manages the domain
docker exec ghostmail ghostctl dns detect -domain <domain>
# Output: "DNS provider for example.com: cloudflare"
```

### Auto-Configure DNS

Ask the user for their DNS provider API key, then:

```bash
docker exec ghostmail ghostctl dns setup \
  -domain <domain> \
  -provider <cloudflare|digitalocean> \
  -api-key <token>
```

This creates all 5 records automatically (A, MX, SPF, DKIM, DMARC). No registrar login needed.

**Supported providers**: Cloudflare, DigitalOcean. For others, fall back to manual DNS instructions.

### Verify DNS Propagation

After setup, verify records have propagated:

```bash
docker exec ghostmail ghostctl dns verify -domain <domain>
```

Output shows PASS/FAIL for each record. Records typically propagate in 5-60 minutes.

### Auto-DNS Flow for Agent

1. Ask user for domain
2. Run `ghostctl dns detect -domain <domain>` to identify provider
3. If supported: ask for API key, run `ghostctl dns setup`
4. If unsupported: show manual DNS records
5. Deploy GhostMail as usual
6. Run `ghostctl dns verify` to confirm

## Option B: Instant Email (No Domain Required)

If the user does NOT own a domain, they can get an instant email address on a shared subdomain. No DNS configuration needed.

### How It Works

A GhostMail operator runs a shared parent domain (e.g., `ghostmail.dev`) with wildcard DNS:
- `*.ghostmail.dev` → server IP (A record)
- `*.ghostmail.dev` → MX record

Users get unique subdomains like `a1b2c3.ghostmail.dev` and email addresses like `admin@a1b2c3.ghostmail.dev`.

### Allocate a Subdomain

```bash
# Random subdomain
docker exec ghostmail ghostctl subdomain create -parent ghostmail.dev

# Custom subdomain (if available)
docker exec ghostmail ghostctl subdomain create -parent ghostmail.dev -name mymail
```

Output:
```
========================================
  Subdomain Allocated!
========================================

  Domain:    a1b2c3.ghostmail.dev
  Email:     admin@a1b2c3.ghostmail.dev
  Password:  <auto-generated>

  Webmail:   https://mail.ghostmail.dev/mail/
  IMAP:      mail.ghostmail.dev:993
  SMTP:      mail.ghostmail.dev:587

  No DNS configuration needed!
  Your email address is ready to use.
========================================
```

### Instant Subdomain Flow for Agent

1. User says "I need an email address" (no domain mentioned)
2. Ask: "Do you have a domain? Or would you like an instant address on ghostmail.dev?"
3. If instant: run `ghostctl subdomain create -parent ghostmail.dev`
4. Return the email address and password
5. User can start sending/receiving immediately

### Adding a Custom Domain Later

Users who start with a subdomain can add their own domain anytime:

```bash
docker exec ghostmail ghostctl domain add -name example.com -primary
docker exec ghostmail ghostctl dkim generate -domain example.com
docker exec ghostmail ghostctl dns setup -domain example.com -provider cloudflare -api-key <token>
```

## Security Notes

- The admin password is generated locally and never transmitted
- All emails are encrypted at rest with per-message envelope encryption
- Even the server admin cannot read stored emails without the user's password
- TLS is automatically provisioned by Caddy via Let's Encrypt
- Session keys are wiped from memory on logout
- DNS API keys are used once for record creation and not stored
