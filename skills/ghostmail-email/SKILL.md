---
name: ghostmail-email
description: "Send, receive, search, and manage emails through a locally deployed GhostMail server. Supports compose, inbox checking, search, alias management, and message organization."
version: 1.0.0
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
    homepage: "https://github.com/ghostmail/ghostmail"
---

# GhostMail Email

Manage your private encrypted email through GhostMail's REST API.

## What This Skill Does

Once GhostMail is deployed (see `ghostmail-deploy` skill), this skill lets you:

- Send emails
- Check your inbox
- Read specific messages
- Search messages
- Create disposable aliases
- Manage folders (move, delete, flag)

## Environment Variables

These must be set before using this skill:

| Variable | Example | Description |
|----------|---------|-------------|
| `GHOSTMAIL_URL` | `http://localhost:8080` | GhostMail server URL |
| `GHOSTMAIL_EMAIL` | `admin@example.com` | Your email address |
| `GHOSTMAIL_PASSWORD` | `your-password` | Your account password |

If not set, ask the user for their GhostMail URL and credentials.

## Trigger Phrases

- "Check my email"
- "Send an email to john@example.com"
- "Search my inbox for invoices"
- "Create a disposable email alias"
- "Read my latest messages"
- "Delete that email"
- "Move that to trash"

## Authentication

All API calls require a session cookie. Authenticate first, then use the cookie for subsequent requests.

### Login

```bash
# Login and capture session cookie
COOKIE_FILE=$(mktemp)
LOGIN_RESULT=$(curl -s -c "$COOKIE_FILE" \
  -X POST "$GHOSTMAIL_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$GHOSTMAIL_EMAIL\", \"password\": \"$GHOSTMAIL_PASSWORD\"}")

echo "$LOGIN_RESULT"
# Expected: {"ok":true,"username":"admin","domain":"example.com","email":"admin@example.com"}
```

If login fails with `{"error":"invalid credentials"}`, ask the user to verify their email and password.

### Logout (when done)

```bash
curl -s -b "$COOKIE_FILE" -X POST "$GHOSTMAIL_URL/api/v1/auth/logout"
rm -f "$COOKIE_FILE"
```

## Operations

### Check Inbox / List Messages

```bash
# List mailboxes (shows INBOX, Sent, Drafts, Trash, Spam with counts)
curl -s -b "$COOKIE_FILE" "$GHOSTMAIL_URL/api/v1/mailboxes"

# List messages in INBOX (paginated)
curl -s -b "$COOKIE_FILE" "$GHOSTMAIL_URL/api/v1/mailboxes/INBOX/messages?page=1&limit=20"

# List messages in other folders
curl -s -b "$COOKIE_FILE" "$GHOSTMAIL_URL/api/v1/mailboxes/Sent/messages?page=1&limit=20"
```

Response format for message list:
```json
{
  "messages": [
    {
      "uid": 1,
      "mailbox_id": 1,
      "from": "sender@example.com",
      "to": "you@example.com",
      "subject": "Meeting tomorrow",
      "date": "2026-03-29T10:00:00Z",
      "flags": ["\\Seen"],
      "size": 1234
    }
  ],
  "total": 42,
  "page": 1,
  "limit": 20
}
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
# Get full message content (decrypted server-side)
curl -s -b "$COOKIE_FILE" "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/MESSAGE_UID"
```

Response includes decrypted headers and body:
```json
{
  "uid": 1,
  "from": "sender@example.com",
  "to": "you@example.com",
  "cc": "",
  "subject": "Meeting tomorrow",
  "date": "2026-03-29T10:00:00Z",
  "body_text": "Hi, just confirming our meeting...",
  "body_html": "<p>Hi, just confirming our meeting...</p>",
  "flags": ["\\Seen"]
}
```

Present the body_text to the user in a readable format. Use body_html only if the user asks for the formatted version.

### Send an Email

```bash
curl -s -b "$COOKIE_FILE" \
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
- Response: `{"ok": true}` on success

When composing for the user:
1. Confirm the recipient, subject, and body before sending
2. Ask "Should I send this?" and show a preview
3. Only send after user confirmation

### Search Messages

```bash
curl -s -b "$COOKIE_FILE" \
  -X POST "$GHOSTMAIL_URL/api/v1/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "search terms here", "mailbox": "INBOX"}'
```

- `mailbox` is optional; omit to search all mailboxes
- Search uses a blind index (privacy-preserving), so only individual words are matched
- Multi-word queries return messages containing ALL words (AND logic)

### Manage Messages

```bash
# Mark as read
curl -s -b "$COOKIE_FILE" \
  -X POST "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/UID/flags" \
  -H "Content-Type: application/json" \
  -d '{"add": ["\\Seen"]}'

# Star/flag a message
curl -s -b "$COOKIE_FILE" \
  -X POST "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/UID/flags" \
  -H "Content-Type: application/json" \
  -d '{"add": ["\\Flagged"]}'

# Move to Trash
curl -s -b "$COOKIE_FILE" \
  -X POST "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/UID/move" \
  -H "Content-Type: application/json" \
  -d '{"destination": "Trash"}'

# Permanently delete (only works from Trash)
curl -s -b "$COOKIE_FILE" \
  -X DELETE "$GHOSTMAIL_URL/api/v1/messages/MAILBOX_ID/UID"
```

### Manage Aliases (Disposable Addresses)

```bash
# List aliases
curl -s -b "$COOKIE_FILE" "$GHOSTMAIL_URL/api/v1/aliases"

# Create a new random alias
curl -s -b "$COOKIE_FILE" \
  -X POST "$GHOSTMAIL_URL/api/v1/aliases" \
  -H "Content-Type: application/json" \
  -d '{"description": "Newsletter signup"}'

# Delete an alias
curl -s -b "$COOKIE_FILE" \
  -X DELETE "$GHOSTMAIL_URL/api/v1/aliases/ALIAS_ID"
```

Aliases are random addresses that forward to the user's real inbox. Useful for:
- Signing up for services without revealing real email
- Tracking which service leaked an address
- Disposable addresses that can be deleted anytime

When creating an alias, ask the user what it's for so you can set a meaningful description.

## Workflow Examples

### "Check my email and summarize what's new"

1. Login
2. GET `/api/v1/mailboxes` to see unread counts
3. GET `/api/v1/mailboxes/INBOX/messages?page=1&limit=10` for recent messages
4. For each unread message, GET full content
5. Summarize: sender, subject, key points from body
6. Logout

### "Send a reply to the email from Alice"

1. Login
2. GET inbox messages, find Alice's message
3. GET full message to read it
4. Compose reply with `in_reply_to` set, subject prefixed with "Re: "
5. Show preview to user, get confirmation
6. POST send
7. Logout

### "Create a throwaway email for this signup"

1. Login
2. POST create alias with description of what it's for
3. Return the alias address to the user
4. Logout

## Important Notes

- All emails are encrypted at rest. Decryption happens server-side during your authenticated session.
- Session keys are wiped from server memory when you logout. Always logout when done.
- The blind search index only matches individual words. Phrases like "exact quote" won't work as a phrase search.
- Messages in Trash are auto-deleted after 30 days. Messages in Spam after 7 days.
- Always confirm with the user before sending an email or deleting a message.
