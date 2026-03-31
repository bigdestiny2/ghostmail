---
name: ghostmail
description: "Zero-knowledge encrypted email on @ghostmail.llc. Sign up, unlock your vault, send/receive/search email. Use when: (1) user wants a private email account, (2) sending or reading encrypted email, (3) managing vault unlock for message decryption. NOT for: non-email messaging, calendar, or contacts."
version: 1.0.0
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

Zero-knowledge encrypted email for AI agents. Every message is encrypted at rest with keys only you can unlock.

## Architecture

GhostMail uses **split-password encryption**:
- **Auth password** = proves identity (IMAP/SMTP login)
- **Vault password** = unlocks message decryption (separate, never stored)

Even the server operator cannot read your email without your vault password.

## Setup

### 1. Get an Account

Check server status:
```bash
curl -s "$GHOSTMAIL_URL/api/v1/provision/status" | jq .
```

Sign up ($10 crypto payment for 100MB inbox):
```bash
curl -s -X POST "$GHOSTMAIL_URL/api/v1/provision/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "yourname",
    "auth_password": "your-login-password",
    "vault_password": "your-vault-password",
    "tx_hash": "0x..."
  }' | jq .
```

Response:
```json
{
  "ok": true,
  "email": "yourname@ghostmail.llc",
  "imap": "mail.ghostmail.llc:993",
  "smtp": "mail.ghostmail.llc:465",
  "note": "Use auth_password for IMAP/SMTP login. Use vault_password to unlock encrypted messages."
}
```

### 2. Configure Himalaya

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

### 3. Unlock Your Vault

Before reading encrypted messages, unlock the vault:
```bash
curl -s -X POST "$GHOSTMAIL_URL/api/v1/vault/unlock" \
  -H "Content-Type: application/json" \
  -H "Cookie: ghostmail_session=$SESSION_TOKEN" \
  -d '{"vault_password": "your-vault-password"}' | jq .
```

Or login + unlock in sequence:
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

Check vault status:
```bash
curl -s "$GHOSTMAIL_URL/api/v1/vault/status" \
  -b "ghostmail_session=$SESSION" | jq .
```

## Email Operations

### List Inbox
```bash
himalaya envelope list
```

### Read a Message
```bash
himalaya message read 42
```

### Send an Email
```bash
cat << 'EOF' | himalaya template send
From: yourname@ghostmail.llc
To: recipient@example.com
Subject: Hello

Message body here.
EOF
```

### Reply to a Message
```bash
himalaya message reply 42
```

### Search
```bash
himalaya envelope list from someone@example.com subject "meeting"
```

### Manage Folders
```bash
himalaya folder list
himalaya message move 42 "Archive"
himalaya message delete 42
```

## Vault Workflow for Agents

When a user asks to read email:

1. **Login** via API to get session cookie
2. **Check vault status** - if locked, ask user for vault password
3. **Unlock vault** with the password (NEVER store the vault password)
4. **Read messages** via himalaya (IMAP will now return decrypted content)
5. Vault auto-locks after 30 minutes of inactivity

IMPORTANT: Never persist the vault password to disk, env vars, or config files. Always prompt the user interactively each time vault access is needed.

## Lock Vault

Explicitly lock when done:
```bash
curl -s -X POST "$GHOSTMAIL_URL/api/v1/vault/lock" \
  -b "ghostmail_session=$SESSION" | jq .
```

## Verify Payment
```bash
curl -s "$GHOSTMAIL_URL/api/v1/provision/verify/0x..." | jq .
```

## One-Line Install

```bash
brew install himalaya && echo 'GHOSTMAIL_URL=https://mail.ghostmail.llc:8443' >> ~/.openclaw/.env
```

## Security Notes

- All messages encrypted at rest with X25519 + AES-256-GCM
- Vault password derives decryption keys via Argon2id (64MB, 3 iterations)
- Private keys exist in server RAM only during active vault sessions
- Server operator cannot read user email (zero-knowledge)
- 100MB quota per account, DKIM-signed outbound mail
