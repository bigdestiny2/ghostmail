---
name: ghostmail-email
description: "Send, receive, search, and manage emails through a self-hosted GhostMail server. Supports vault unlock for message decryption, compose, inbox checking, search, alias management, and message organization."
version: 1.1.0
metadata:
  openclaw:
    requires:
      bins:
        - curl
      env:
        - GHOSTMAIL_URL
        - GHOSTMAIL_EMAIL
        - GHOSTMAIL_PASSWORD
    primaryEnv: GHOSTMAIL_PASSWORD
    emoji: "\U0001F4EC"
    homepage: "https://github.com/bigdestiny2/ghostmail"
---

# GhostMail Email

Manage your private encrypted email through GhostMail's REST API.

## What This Skill Does

Once GhostMail is deployed (see `ghostmail-deploy` skill), this skill lets you:

- Send emails
- Check your inbox
- Read specific messages (requires vault unlock for encrypted messages)
- Search messages
- Create disposable aliases
- Manage folders (move, delete, flag)

## Environment Variables

These must be set before using this skill:

| Variable | Example | Description |
|----------|---------|-------------|
| `GHOSTMAIL_URL` | `https://mail.example.com:8443` | GhostMail server URL |
| `GHOSTMAIL_EMAIL` | `admin@example.com` | Your email address |
| `GHOSTMAIL_PASSWORD` | `your-auth-password` | Your auth password (for login) |

If not set, ask the user for their GhostMail URL and credentials.

CRITICAL: The vault password is NEVER stored in env vars. Always ask the user interactively.

## Authentication

All API calls require a session cookie. Authenticate first, then use the cookie for subsequent requests.

### Login

```bash
# Login and capture session cookie
SESSION=$(curl -sk -X POST "$GHOSTMAIL_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$GHOSTMAIL_EMAIL\", \"password\": \"$GHOSTMAIL_PASSWORD\"}" \
  -c - | grep ghostmail_session | awk '{print $NF}')

echo "Session: $SESSION"
```

If login fails with `{"error":"invalid credentials"}`, ask the user to verify their email and password.

### Vault Unlock (Required for Reading Encrypted Messages)

If the login response includes `"vault_locked": true`, messages are encrypted and need the vault password to decrypt:

```bash
# Check vault status
curl -sk -b "ghostmail_session=$SESSION" "$GHOSTMAIL_URL/api/v1/vault/status"
# Returns: {"vault_enabled":true,"locked":true}

# Unlock vault (ask user for vault password interactively)
curl -sk -X POST "$GHOSTMAIL_URL/api/v1/vault/unlock" \
  -H "Content-Type: application/json" \
  -b "ghostmail_session=$SESSION" \
  -d '{"vault_password": "USER_VAULT_PASSWORD"}'
# Returns: {"ok":true,"expires_at":"..."}
```

- The vault auto-locks after 30 minutes
- You must ask the user for their vault password each session — NEVER store or cache it
- Sending email does NOT require vault unlock, only reading encrypted messages does

### Logout (when done)

```bash
curl -sk -b "ghostmail_session=$SESSION" -X POST "$GHOSTMAIL_URL/api/v1/auth/logout"
```

## Operations

### Check Inbox / List Messages

```bash
# List mailboxes (shows INBOX, Sent, Drafts, Trash, Spam with counts)
curl -sk -b "ghostmail_session=$SESSION" "$GHOSTMAIL_URL/api/v1/mailboxes"

# List messages in INBOX (paginated)
curl -sk -b "ghostmail_session=$SESSION" "$GHOSTMAIL_URL/api/v1/mailboxes/INBOX/messages?page=1&limit=20"

# List messages in other folders
curl -sk -b "ghostmail_session=$SESSION" "$GHOSTMAIL_URL/api/v1/mailboxes/Sent/messages?page=1&limit=20"
```

When presenting messages to the user, format them as a readable list:
```
Inbox (3 unread / 42 total):

1. [NEW] From: alice@example.com - "Project Update" - Mar 29
2. [NEW] From: bob@corp.com - "Invoice #1234" - Mar 28
3.       From: carol@example.com - "Re: Meeting notes" - Mar 27
```

### Read a Specific Message

```bash
# Get full message content (decrypted if vault is unlocked)
curl -sk -b "ghostmail_session=$SESSION" "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/MESSAGE_UID"
```

If the vault is locked, the response will contain encrypted data. Prompt the user: "Your vault is locked. Enter your vault password to decrypt messages."

### Send an Email

```bash
curl -sk -b "ghostmail_session=$SESSION" \
  -X POST "$GHOSTMAIL_URL/api/v1/messages/send" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "recipient@example.com",
    "cc": "",
    "bcc": "",
    "subject": "Subject line here",
    "body": "Plain text email body here",
    "in_reply_to": ""
  }'
```

- `to`, `cc`, `bcc`: Comma-separated email addresses
- `in_reply_to`: Set to the original message's Message-ID when replying
- Sending does NOT require vault unlock

When composing for the user:
1. Confirm the recipient, subject, and body before sending
2. Ask "Should I send this?" and show a preview
3. Only send after user confirmation

### Search Messages

```bash
curl -sk -b "ghostmail_session=$SESSION" \
  -X POST "$GHOSTMAIL_URL/api/v1/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "search terms here", "mailbox": "INBOX"}'
```

- `mailbox` is optional; omit to search all mailboxes
- Search uses a blind index (privacy-preserving), so only individual words are matched

### Manage Messages

```bash
# Mark as read
curl -sk -b "ghostmail_session=$SESSION" \
  -X POST "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/UID/flags" \
  -H "Content-Type: application/json" \
  -d '{"add": ["\\Seen"]}'

# Move to Trash
curl -sk -b "ghostmail_session=$SESSION" \
  -X POST "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/UID/move" \
  -H "Content-Type: application/json" \
  -d '{"destination": "Trash"}'

# Permanently delete (only works from Trash)
curl -sk -b "ghostmail_session=$SESSION" \
  -X DELETE "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/UID"
```

### Manage Aliases

```bash
# List aliases
curl -sk -b "ghostmail_session=$SESSION" "$GHOSTMAIL_URL/api/v1/aliases"

# Create a new random alias
curl -sk -b "ghostmail_session=$SESSION" \
  -X POST "$GHOSTMAIL_URL/api/v1/aliases" \
  -H "Content-Type: application/json" \
  -d '{"description": "Newsletter signup"}'

# Delete an alias
curl -sk -b "ghostmail_session=$SESSION" \
  -X DELETE "$GHOSTMAIL_URL/api/v1/aliases/ALIAS_ID"
```

## Workflow: Reading Email (Vault User)

1. Login with auth password
2. Check vault status — if locked, ask user: "Enter your vault password to decrypt messages"
3. Unlock vault with user's vault password
4. List mailboxes, fetch messages — now decrypted
5. Vault auto-locks after 30 minutes
6. Logout when done

## Important Notes

- **Vault users**: Auth password for login, vault password for decryption. Never store the vault password.
- **Legacy users** (single password): Login derives both auth and decryption keys automatically.
- Session keys are wiped from server memory when you logout or the vault TTL expires.
- Messages in Trash auto-delete after 30 days. Messages in Spam after 7 days.
- Always confirm with the user before sending or deleting.
