---
name: ghostmail-email
description: "Check inbox, read, send, search, and manage encrypted emails through GhostMail. On start: login, show mailbox summary, and ask what the user wants to do. Supports vault unlock, OTV links, compose links, aliases, and message organization."
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

## Default Behavior (IMPORTANT)

When this skill is invoked without a specific request, follow this startup sequence:

1. **Login** using the env vars (GHOSTMAIL_URL, GHOSTMAIL_EMAIL, GHOSTMAIL_PASSWORD)
2. **Check vault status** — if locked, ask the user for their vault password
3. **List mailboxes** — show a summary like:
   ```
   📬 Inbox (3 unread / 42 total)
   📤 Sent (15)
   📝 Drafts (1)
   🗑️ Trash (2)
   ```
4. **Ask the user what they'd like to do**: "You have 3 unread messages. Want to read them, compose a new email, or something else?"

Do NOT jump straight to composing an email. The default action is to show the inbox summary and wait for instructions.

## What This Skill Does

Once GhostMail is deployed (see `ghostmail-deploy` skill), this skill lets you:

- Check your inbox and read messages
- Send emails
- Search messages (requires vault unlock for encrypted messages)
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

## Privacy Mode: One-Time View Links (CRITICAL for Telegram/Chat Agents)

**IMPORTANT**: When operating through a messaging platform (Telegram, Slack, Discord, etc.), NEVER paste email content directly into the chat. Instead, use One-Time View (OTV) links. This prevents email content from being stored in chat history.

### Why OTV Links?

If you paste email content into Telegram:
- The plaintext sits in Telegram's chat history forever
- The user must manually delete messages to protect privacy
- This defeats the purpose of zero-knowledge encryption

### Creating a One-Time View Link

```bash
# Create an OTV link for a specific message
curl -sk -b "ghostmail_session=$SESSION" \
  -X POST "$GHOSTMAIL_URL/api/v1/otv/create" \
  -H "Content-Type: application/json" \
  -d '{"mailbox_id": MAILBOX_ID, "uid": MESSAGE_UID}'
# Returns: {"url":"https://mail.example.com:8443/mail/view/abc123...","expires_at":"...","expires_in":300}
```

### Agent Workflow for Reading Email

Instead of pasting message content, send the user an OTV link:

```
You have a new email:
  From: alice@example.com
  Subject: Project Update
  Date: Apr 1, 2026

Read it here (expires in 5 min, single use):
https://mail.example.com:8443/mail/view/a8f3c9e1...
```

The user clicks the link in their browser and sees the decrypted message. The link self-destructs after one view.

### OTV Rules

- Links expire after **5 minutes** or after **one view** (whichever comes first)
- Max **100 active links** per user at a time
- Requires vault to be unlocked (message is decrypted server-side when link is created)
- The decrypted content is held in server RAM only, never written to disk
- Always include From, Subject, and Date as metadata in chat — these are headers, not content

## Privacy Mode: Compose Links (for Sending)

When the user wants to compose an email, give them a compose link instead of asking them to type the message in chat:

```
Compose your email here (opens in browser):
https://mail.example.com:8443/mail/compose?to=bob@example.com&subject=Re%3A%20Meeting
```

### Compose Link Parameters

| Parameter | Description |
|-----------|-------------|
| `to` | Pre-filled recipient |
| `subject` | Pre-filled subject (URL-encode special chars) |
| `cc` | Pre-filled CC |
| `body` | Pre-filled body text |

This way the user types their message in the encrypted webmail UI, not in Telegram chat.

## Workflow: Chat Agent (Telegram/Slack/Discord)

1. Login with auth password
2. Unlock vault if needed
3. List mailboxes and messages — show **metadata only** (from, subject, date) in chat
4. For reading: create OTV link, send link to user
5. For composing: send compose link to user
6. For quick actions (delete, move, flag): handle directly via API
7. **NEVER paste email body text into the chat**
8. Logout when done

## Workflow: Reading Email (Direct/CLI)

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
- **Chat agents MUST use OTV links** — never paste email content into messaging platforms.
