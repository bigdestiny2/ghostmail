# GhostMail

A zero-knowledge encrypted email server in a single binary. Self-hosted SMTP, IMAP, webmail, and admin panel with per-message envelope encryption — even the server admin can't read your mail.

## Features

- **Zero-knowledge encryption** — every message encrypted with X25519 + AES-256-GCM before hitting disk
- **SMTP** inbound (port 25) and submission (port 587) with DKIM signing
- **IMAP** with on-the-fly decryption (port 993)
- **Webmail** — browser-based email client, no IMAP client needed
- **Admin panel** — user management, domain config, queue monitoring
- **Blind search** — HMAC-SHA256 search index lets you search encrypted mail without exposing plaintext
- **Disposable aliases** — random forwarding addresses, create/delete anytime
- **Privacy headers** — strips Received, User-Agent, X-Originating-IP by default
- **DKIM/SPF/DMARC** — full email authentication out of the box
- **Single binary** — Go, SQLite, no external dependencies
- **Docker one-click deploy** — `docker compose up` and you're running

## Quick Start

### One-Line Install

```bash
curl -fsSL https://raw.githubusercontent.com/ghostmail/ghostmail/main/install.sh | sh
```

This will:
1. Prompt for your domain
2. Generate a secure admin password
3. Deploy GhostMail + Caddy (TLS) via Docker Compose
4. Print your login credentials and DNS records

### Docker Compose

```bash
git clone https://github.com/ghostmail/ghostmail.git
cd ghostmail
cp .env.example .env
# Edit .env with your domain and password
docker compose up -d
```

### OpenClaw

If you're running [OpenClaw](https://openclaw.ai), install the GhostMail skills:

```bash
npx clawhub install ghostmail-deploy
npx clawhub install ghostmail-email
```

Then tell your agent: *"Deploy my email server for mydomain.com"*

### Build from Source

```bash
git clone https://github.com/ghostmail/ghostmail.git
cd ghostmail
make build
./bin/ghostmail -config configs/ghostmail.example.toml
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Clients                        │
│         IMAP (993)  │  Webmail (443)             │
└────────┬────────────┴──────────┬────────────────┘
         │                       │
┌────────▼───────────────────────▼────────────────┐
│              GhostMail Server                    │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │   SMTP   │  │   IMAP   │  │   Webmail    │  │
│  │  Server   │  │  Server   │  │   + Admin    │  │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  │
│       │              │               │           │
│  ┌────▼──────────────▼───────────────▼───────┐  │
│  │            Crypto Service                  │  │
│  │  Argon2id │ X25519 │ AES-256-GCM │ HKDF  │  │
│  └────────────────────┬──────────────────────┘  │
│                       │                          │
│  ┌────────────────────▼──────────────────────┐  │
│  │          SQLite (encrypted at rest)        │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Encryption Model

GhostMail uses a four-layer encryption model:

| Layer | Technology | Protects Against |
|-------|-----------|-----------------|
| Transport | TLS 1.3 | Network sniffing |
| Envelope | X25519 + AES-256-GCM (per-message) | Server compromise, admin access |
| External | DKIM + optional PGP | Spoofing, transit interception |
| At-rest | Encrypted SQLite blobs | Disk theft, backups |

**Key hierarchy:**

```
Password
  └─ Argon2id (time=3, mem=64MB, threads=4)
       └─ Master Key (256-bit)
            ├─ HKDF → Auth Hash (stored, for login verification)
            ├─ HKDF → X25519 Private Key (decrypt messages)
            ├─ HKDF → Search Key (blind index HMAC)
            └─ HKDF → Envelope Keys (per-message AES-256-GCM)
```

The server never stores your password or private key. Keys are derived on login, held in memory for your session, and wiped on logout.

## DNS Records

After deployment, add these records at your domain registrar:

| Type | Name | Value |
|------|------|-------|
| A | `mail.example.com` | `<your-server-ip>` |
| MX | `example.com` | `mail.example.com` (priority 10) |
| TXT | `example.com` | `v=spf1 mx a -all` |
| TXT | `_dmarc.example.com` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s` |

Get your DKIM record:
```bash
docker exec ghostmail ghostctl dkim dns -domain example.com
```

## API Reference

GhostMail exposes a REST API on the admin/webmail port for programmatic access.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/login` | Authenticate, get session cookie |
| `POST` | `/api/v1/auth/logout` | Destroy session, wipe keys |
| `GET` | `/api/v1/mailboxes` | List mailboxes with counts |
| `GET` | `/api/v1/mailboxes/{name}/messages` | Paginated message list |
| `GET` | `/api/v1/messages/{mailbox}/{uid}` | Read full decrypted message |
| `POST` | `/api/v1/messages/send` | Send an email |
| `POST` | `/api/v1/messages/{mailbox}/{uid}/flags` | Update message flags |
| `POST` | `/api/v1/messages/{mailbox}/{uid}/move` | Move to another mailbox |
| `DELETE` | `/api/v1/messages/{mailbox}/{uid}` | Delete a message |
| `POST` | `/api/v1/search` | Blind index search |
| `GET` | `/api/v1/aliases` | List aliases |
| `POST` | `/api/v1/aliases` | Create random alias |
| `DELETE` | `/api/v1/aliases/{id}` | Delete alias |
| `GET` | `/health` | Health check (no auth) |

## Configuration

GhostMail uses a TOML config file. See [`configs/ghostmail.example.toml`](configs/ghostmail.example.toml) for all options.

Key sections:

```toml
[server]
hostname = "mail.example.com"
data_dir = "/var/lib/ghostmail"

[smtp]
listen_addr = ":25"
submission_addr = ":587"

[imap]
listen_addr = ":993"

[admin]
enabled = true
listen_addr = ":8080"

[webmail]
enabled = true

[privacy]
strip_received_headers = true
strip_user_agent = true
log_ips = false

[crypto]
argon2_time = 3
argon2_memory = 65536
```

## CLI Tools

```bash
# User management
ghostctl user create -username alice -domain example.com -password secret
ghostctl user list
ghostctl user delete -email alice@example.com

# Domain management
ghostctl domain add -name example.com -primary
ghostctl domain list

# DKIM
ghostctl dkim generate -domain example.com
ghostctl dkim dns -domain example.com

# Queue inspection
ghostctl queue list
ghostctl queue retry -id <message-id>
```

## System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 core | 2 cores |
| RAM | 256 MB | 512 MB |
| Disk | 1 GB | 10 GB+ |
| OS | Linux (amd64/arm64) | Ubuntu 22.04+ / Debian 12+ |
| Ports | 25, 587, 993, 80, 443 | Open inbound on firewall |

## License

AGPLv3 — see [LICENSE](LICENSE) for details.

If you modify GhostMail and offer it as a service, you must publish your changes.
