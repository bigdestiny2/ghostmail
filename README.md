# GhostMail

Zero-knowledge encrypted email in a single binary. Self-hosted SMTP, IMAP, webmail, and admin panel with per-message envelope encryption — even the server operator can't read your mail.

## Get a @ghostmail.llc inbox

Don't want to self-host? Get an encrypted inbox for **$10 in crypto** (ETH, Base, BSC, or Solana):

```bash
# 1. Check available chains and wallet addresses
curl -s https://mail.ghostmail.llc:8443/api/v1/provision/status | jq .

# 2. Send $10 to the wallet for your preferred chain

# 3. Sign up with your transaction hash
curl -s -X POST https://mail.ghostmail.llc:8443/api/v1/provision/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "yourname",
    "auth_password": "your-login-password",
    "vault_password": "your-vault-password",
    "tx_hash": "0x...",
    "chain": "base"
  }' | jq .
```

You get `yourname@ghostmail.llc` with 100MB storage. Every message encrypted at rest — only you can decrypt.

### OpenClaw Users

```bash
brew install himalaya
echo 'GHOSTMAIL_URL=https://mail.ghostmail.llc:8443' >> ~/.openclaw/.env
```

Then tell your agent: *"Set me up with a GhostMail inbox"* — it handles payment, signup, and config.

## Features

- **Zero-knowledge encryption** — X25519 + AES-256-GCM per-message envelope encryption
- **Split-password security** — separate auth password (login) and vault password (decrypt messages)
- **Vault unlock** — private keys held in RAM only during active sessions (30min TTL), never stored
- **Self-service signup** — $10 crypto payment, on-chain verification, instant account creation
- **Multi-chain payments** — ETH, Base, BSC, Solana accepted
- **SMTP** inbound (port 25) and submission (port 587) with DKIM signing
- **IMAP** with on-the-fly decryption (port 993)
- **Webmail** — browser-based email client, no IMAP client needed
- **Admin panel** — user management, domain config, queue monitoring
- **Blind search** — HMAC-SHA256 search index lets you search encrypted mail without exposing plaintext
- **Disposable aliases** — random forwarding addresses, create/delete anytime
- **Privacy headers** — strips Received, User-Agent, X-Originating-IP by default
- **DKIM/SPF/DMARC** — full email authentication out of the box
- **Tor hidden service** — optional .onion access
- **Single binary** — Go, SQLite, no external dependencies
- **Docker one-click deploy** — `docker compose up` and you're running

## How Vault Encryption Works

GhostMail uses **split-password encryption** for zero-knowledge security:

```
Auth Password (login)              Vault Password (decrypt)
       │                                    │
       ▼                                    ▼
   Argon2id                             Argon2id
       │                                    │
       ▼                                    ▼
   Auth Hash ──► stored             Vault Key ──► wraps X25519 private key
   (proves identity)                (never stored, entered each session)
```

- **Auth password** = proves your identity for IMAP/SMTP login
- **Vault password** = unlocks your private key to decrypt messages

The server stores your auth hash (for login verification) and your wrapped private key (encrypted by your vault password). It **never** stores your vault password or plaintext private key. Even a server compromise yields only ciphertext.

### Vault Session Lifecycle

1. Login with auth password (IMAP/SMTP/webmail) — can send email, see encrypted blobs
2. Unlock vault with vault password — private key derived in RAM, messages become readable
3. Read/search encrypted email normally
4. Vault auto-locks after 30 minutes — private key wiped from memory
5. Re-enter vault password to continue reading

## Quick Start (Self-Hosted)

### Docker Compose

```bash
git clone https://github.com/bigdestiny2/ghostmail.git
cd ghostmail
cp .env.example .env
# Edit .env with your domain and password
docker compose up -d
```

### Build from Source

```bash
git clone https://github.com/bigdestiny2/ghostmail.git
cd ghostmail
make build
./bin/ghostmail -config configs/ghostmail.example.toml
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Clients                            │
│       IMAP (993)  │  Webmail (443)  │  OpenClaw      │
└──────┬────────────┴────────┬────────┴───────┬───────┘
       │                     │                │
┌──────▼─────────────────────▼────────────────▼───────┐
│               GhostMail Server                       │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │   SMTP   │  │   IMAP   │  │ Admin + Webmail   │  │
│  │  Server   │  │  Server   │  │ + Provisioning    │  │
│  └────┬─────┘  └────┬─────┘  └────────┬──────────┘  │
│       │              │                 │              │
│  ┌────▼──────────────▼─────────────────▼──────────┐  │
│  │              Crypto Service                     │  │
│  │  Argon2id │ X25519 │ AES-256-GCM │ HKDF       │  │
│  └──────────────────────┬─────────────────────────┘  │
│                         │                             │
│  ┌──────────────────────▼─────────────────────────┐  │
│  │      Vault Store (in-memory session keys)       │  │
│  │      30min TTL │ auto-sweep │ key wipe          │  │
│  └──────────────────────┬─────────────────────────┘  │
│                         │                             │
│  ┌──────────────────────▼─────────────────────────┐  │
│  │         SQLite (encrypted blobs only)           │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

## Encryption Model

| Layer | Technology | Protects Against |
|-------|-----------|-----------------|
| Transport | TLS 1.2+ | Network sniffing |
| Envelope | X25519 + AES-256-GCM (per-message) | Server compromise, admin access |
| Vault | Argon2id + wrapped private key | Key theft, memory dumps |
| Search | HMAC-SHA256 blind index | Search query exposure |
| External | DKIM + optional PGP | Spoofing, transit interception |

**Key derivation:**

```
Auth Password                    Vault Password
     │                                │
     ▼                                ▼
  Argon2id (64MB, 3 iter)         Argon2id (64MB, 3 iter)
     │                                │
     ├─► Auth Hash (stored)           ├─► Vault Hash (stored)
     └─► Search Key (HMAC)           └─► Vault Key
                                           │
                                           ▼
                                      Unwrap X25519 Private Key
                                      (AES-256-GCM, stored encrypted)
                                           │
                                           ▼
                                      Decrypt per-message envelope keys
                                           │
                                           ▼
                                      Decrypt message body (AES-256-GCM)
```

## API Reference

### Provisioning (no auth required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/provision/status` | Available chains, wallet addresses, pricing |
| `POST` | `/api/v1/provision/signup` | Create account with crypto payment |
| `GET` | `/api/v1/provision/verify/{tx}` | Check payment status |

### Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/login` | Authenticate, get session cookie |
| `POST` | `/api/v1/auth/logout` | Destroy session, wipe keys |

### Vault

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/vault/unlock` | Unlock vault with vault password |
| `POST` | `/api/v1/vault/lock` | Lock vault, wipe keys from memory |
| `GET` | `/api/v1/vault/status` | Check if vault is locked/unlocked |

### Mailboxes & Messages

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/mailboxes` | List mailboxes with counts |
| `GET` | `/api/v1/mailboxes/{name}/messages` | Paginated message list |
| `GET` | `/api/v1/messages/{mailbox}/{uid}` | Read full decrypted message |
| `POST` | `/api/v1/messages/send` | Send an email |
| `POST` | `/api/v1/messages/{mailbox}/{uid}/flags` | Update message flags |
| `POST` | `/api/v1/messages/{mailbox}/{uid}/move` | Move to another mailbox |
| `DELETE` | `/api/v1/messages/{mailbox}/{uid}` | Delete a message |
| `POST` | `/api/v1/search` | Blind index search |

### Aliases

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/aliases` | List aliases |
| `POST` | `/api/v1/aliases` | Create random alias |
| `DELETE` | `/api/v1/aliases/{id}` | Delete alias |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check (no auth) |

## Configuration

GhostMail uses a TOML config file. See [`configs/ghostmail.example.toml`](configs/ghostmail.example.toml) for all options.

```toml
[server]
hostname = "mail.example.com"
data_dir = "/var/lib/ghostmail"

[tls]
cert_file = "/path/to/fullchain.pem"
key_file = "/path/to/privkey.pem"

[smtp]
listen_addr = ":25"
submission_addr = ":587"

[imap]
listen_addr = ":993"

[crypto]
argon2_time = 3
argon2_memory = 65536
vault_ttl = "30m"

[admin]
enabled = true
listen_addr = ":8443"

[webmail]
enabled = true

[privacy]
strip_received_headers = true
strip_user_agent = true
log_ips = false

[provisioning]
enabled = true
domain = "ghostmail.llc"
price_usd = 10.0
default_quota_bytes = 104857600  # 100MB

[provisioning.wallets]
evm = "0x..."      # ETH, Base, BSC
solana = "..."      # Solana address
```

## Supported Payment Chains

| Chain | Token | Typical Fee |
|-------|-------|-------------|
| Ethereum | ETH | ~$1-5 |
| Base | ETH | ~$0.01 |
| BSC | BNB | ~$0.05 |
| Solana | SOL | ~$0.001 |

Payments are verified on-chain via public RPC endpoints. No third-party payment processor.

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
ghostctl dkim dns -domain example.com
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
| Ports | 25, 465, 587, 993, 8443 | Open inbound on firewall |

## Security

- X25519 + AES-256-GCM envelope encryption per message
- Argon2id key derivation (64MB memory, 3 iterations)
- Split auth/vault passwords — server never holds decryption keys
- Private keys in server RAM only during active vault sessions (30min TTL)
- Zero-knowledge: server operator cannot read user email
- DKIM-signed outbound, SPF + DMARC enforced
- Privacy header stripping (Received, User-Agent, X-Originating-IP)
- Rate limiting on auth and API endpoints
- 100MB quota per provisioned account

## License

AGPLv3 — see [LICENSE](LICENSE) for details.

If you modify GhostMail and offer it as a service, you must publish your changes.
