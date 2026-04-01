---
name: ghostmail
description: "Zero-knowledge encrypted email on @ghostmail.llc. Sign up with crypto ($10), unlock your vault, send/receive/search email. Supports ETH, Base, BSC, and Solana payments. Use when: (1) user wants a private email account, (2) sending or reading encrypted email, (3) managing vault unlock for message decryption. NOT for: non-email messaging, calendar, or contacts."
version: 1.1.0
metadata:
  openclaw:
    emoji: "\U0001F47B"
    requires:
      bins:
        - curl
        - himalaya
      env:
        - GHOSTMAIL_URL
    primaryEnv: GHOSTMAIL_URL
    install:
      - id: brew-himalaya
        kind: brew
        formula: himalaya
        bins: [himalaya]
        label: "Install Himalaya email CLI (brew)"
---

# GhostMail Skill

Zero-knowledge encrypted email for AI agents. $10 crypto payment gets you a @ghostmail.llc inbox with 100MB storage. Every message encrypted at rest — only you can decrypt.

## Default Behavior (IMPORTANT)

When this skill is invoked without a specific request (e.g. user just says "check my email" or "ghostmail"), follow this startup sequence:

1. **Login** using env vars (GHOSTMAIL_URL, credentials)
2. **Check vault status** — if locked, ask the user for their vault password
3. **List mailboxes** — show a summary like:
   ```
   📬 Inbox (3 unread / 42 total)
   📤 Sent (15)
   🗑️ Trash (2)
   ```
4. **Ask the user what they'd like to do**: "You have 3 unread messages. Want to read them, compose a new email, or something else?"

Do NOT jump straight to composing an email or asking for a recipient. The default action is to show the inbox summary and wait for instructions.

## How It Works

GhostMail uses **split-password encryption**:
- **Auth password** = proves identity (IMAP/SMTP login)
- **Vault password** = unlocks message decryption (never stored anywhere)

Even the server operator cannot read your email.

## Quick Start

### 1. Check Availability and Payment Info

```bash
curl -s "$GHOSTMAIL_URL/api/v1/provision/status" | jq .
```

Response shows accepted chains and wallet addresses:
```json
{
  "available": true,
  "domain": "ghostmail.llc",
  "price_usd": 10,
  "quota_mb": 100,
  "chains": [
    {"chain": "eth", "address": "0xC95DE0AB0f75285711Fff6F5C82190A51D94B0Cc"},
    {"chain": "base", "address": "0xC95DE0AB0f75285711Fff6F5C82190A51D94B0Cc"},
    {"chain": "bsc", "address": "0xC95DE0AB0f75285711Fff6F5C82190A51D94B0Cc"},
    {"chain": "solana", "address": "4AFQA41FE7Nx8zqcXUqKy3TffKTneLZoQpChRkPS1gVb"}
  ],
  "imap": "mail.ghostmail.llc:993",
  "smtp": "mail.ghostmail.llc:465"
}
```

### 2. Pay and Sign Up

User sends $10 in crypto to one of the wallet addresses above. Then:

```bash
curl -s -X POST "$GHOSTMAIL_URL/api/v1/provision/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "yourname",
    "auth_password": "your-login-password",
    "vault_password": "your-vault-password",
    "tx_hash": "0x...",
    "chain": "base"
  }' | jq .
```

Supported chains: `eth`, `base`, `bsc`, `solana`

The server verifies the transaction on-chain before creating the account. Fake transactions are rejected.

### 3. Configure Himalaya

Create `~/.config/himalaya/config.toml`:
```toml
[accounts.ghostmail]
email = "yourname@ghostmail.llc"
display-name = "Your Name"
default = true

backend.type = "imap"
backend.host = "mail.ghostmail.llc"
backend.port = 993
backend.encryption.type = "tls"
backend.login = "yourname@ghostmail.llc"
backend.auth.type = "password"
backend.auth.cmd = "echo your-login-password"

message.send.backend.type = "smtp"
message.send.backend.host = "mail.ghostmail.llc"
message.send.backend.port = 465
message.send.backend.encryption.type = "tls"
message.send.backend.login = "yourname@ghostmail.llc"
message.send.backend.auth.type = "password"
message.send.backend.auth.cmd = "echo your-login-password"
```

### 4. Unlock Your Vault

Before reading encrypted messages, unlock the vault. This must be done each session — the vault password is never stored.

```bash
# Step 1: Login (get session cookie)
SESSION=$(curl -s -X POST "$GHOSTMAIL_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "yourname@ghostmail.llc", "password": "your-login-password"}' \
  -c - | grep ghostmail_session | awk '{print $NF}')

# Step 2: Unlock vault
curl -s -X POST "$GHOSTMAIL_URL/api/v1/vault/unlock" \
  -H "Content-Type: application/json" \
  -b "ghostmail_session=$SESSION" \
  -d '{"vault_password": "your-vault-password"}' | jq .
```

## Agent Workflow

When a user asks you to set up GhostMail or read their email, follow this flow:

### New Account
1. Call `/api/v1/provision/status` to get payment addresses
2. Ask user which chain they want to pay on
3. Show them the wallet address and amount ($10)
4. User sends payment and gives you the transaction hash
5. Call `/api/v1/provision/signup` with username, passwords, tx_hash, chain
6. Generate himalaya config and write to `~/.config/himalaya/config.toml`
7. Done — user can now send/receive email

### Reading Email (Vault Required)
1. Login via `/api/v1/auth/login` to get session cookie
2. Check `/api/v1/vault/status` — if locked, ask: "Enter your vault password to decrypt messages"
3. User provides vault password (in the chat, not stored)
4. Call `/api/v1/vault/unlock` with the password
5. Now `himalaya envelope list` and `himalaya message read` return decrypted content
6. Vault auto-locks after 30 minutes

### Sending Email (No Vault Needed)
Sending only needs the auth password (already in himalaya config):
```bash
cat << 'EOF' | himalaya template send
From: yourname@ghostmail.llc
To: recipient@example.com
Subject: Hello

Message body here.
EOF
```

CRITICAL: NEVER persist the vault password. NEVER write it to files, env vars, or config. Always ask the user interactively.

## Email Commands

```bash
# List inbox
himalaya envelope list

# Read message
himalaya message read 42

# Send email
cat << 'EOF' | himalaya template send
From: user@ghostmail.llc
To: someone@example.com
Subject: Subject line

Body text
EOF

# Reply
himalaya message reply 42

# Search
himalaya envelope list from someone@example.com subject "keyword"

# Folders
himalaya folder list
himalaya message move 42 "Archive"
himalaya message delete 42

# Attachments
himalaya attachment download 42 --dir ~/Downloads
```

## Vault Management

```bash
# Check status
curl -s "$GHOSTMAIL_URL/api/v1/vault/status" -b "ghostmail_session=$SESSION" | jq .

# Lock explicitly
curl -s -X POST "$GHOSTMAIL_URL/api/v1/vault/lock" -b "ghostmail_session=$SESSION" | jq .

# Verify a payment
curl -s "$GHOSTMAIL_URL/api/v1/provision/verify/0x..." | jq .
```

## One-Line Install

```bash
brew install himalaya && echo 'GHOSTMAIL_URL=https://mail.ghostmail.llc:8443' >> ~/.openclaw/.env
```

## Security

- X25519 + AES-256-GCM envelope encryption per message
- Argon2id key derivation (64MB memory, 3 iterations)
- Private keys in server RAM only during active vault sessions (30min TTL)
- Zero-knowledge: server operator cannot read user email
- DKIM-signed outbound, SPF + DMARC enforced
- 100MB quota per account
