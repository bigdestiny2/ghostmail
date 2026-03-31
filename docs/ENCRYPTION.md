# GhostMail Encryption Architecture

## The Big Picture

```
  Sender                        GhostMail Server                      Recipient
 ────────                      ─────────────────                     ──────────

 "Hello,                    ┌─────────────────────┐
  here's the           TLS  │                     │  TLS
  invoice"  ──────────────► │  Encrypt with       │ ◄────────────── Login with
            SMTP :587       │  recipient's        │  Webmail/IMAP   password
                            │  public key         │
                            │         │           │        │
                            │         ▼           │        ▼
                            │  ┌─────────────┐    │  ┌──────────┐
                            │  │ ░░░░░░░░░░░ │    │  │ Derive   │
                            │  │ ░CIPHERTEXT░ │    │  │ private  │
                            │  │ ░░░░░░░░░░░ │    │  │ key      │
                            │  └─────────────┘    │  └────┬─────┘
                            │    SQLite on disk    │       │
                            │                     │       ▼
                            │  Server admin sees:  │  Decrypt in
                            │  NOTHING READABLE    │  memory only
                            │                     │       │
                            └─────────────────────┘       ▼

                                                    "Hello,
                                                     here's the
                                                     invoice"
```

---

## 1. Account Creation — Key Generation

When a user account is created, their password generates all the cryptographic material they'll ever need.

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                     USER'S PASSWORD                              │
  │                    (never stored)                                │
  └──────────────────────────┬───────────────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                       ARGON2ID                                   │
  │              (time=3, memory=64MB, threads=4)                    │
  │                                                                  │
  │  Expensive on purpose — makes brute-forcing slow.               │
  │  A GPU trying 1 billion passwords would take centuries.          │
  └──────────────────────────┬───────────────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                   MASTER KEY (256-bit)                            │
  │                   (never stored)                                 │
  └──────┬──────────────────┬──────────────────────┬─────────────────┘
         │                  │                      │
         ▼                  ▼                      ▼
  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────┐
  │   HKDF       │  │    HKDF       │  │       HKDF           │
  │  "auth"      │  │  "encrypt"    │  │     "search"         │
  └──────┬───────┘  └───────┬───────┘  └──────────┬───────────┘
         │                  │                      │
         ▼                  ▼                      ▼
  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────┐
  │  Auth Hash   │  │  Encryption   │  │    Search Key         │
  │              │  │  Key          │  │                        │
  │  Stored in   │  │  Wraps the    │  │  Generates blind      │
  │  database    │  │  private key  │  │  search tokens        │
  │  for login   │  │              │  │                        │
  │  verification│  │  ┌─────────┐ │  │  (HMAC-SHA256 per     │
  │              │  │  │ X25519  │ │  │   word in email)       │
  │              │  │  │ Private │ │  │                        │
  │              │  │  │ Key     │ │  │                        │
  │              │  │  │ (wrap   │ │  │                        │
  │              │  │  │ with    │ │  │                        │
  │              │  │  │ AES-GCM)│ │  │                        │
  │              │  │  └────┬────┘ │  │                        │
  └──────────────┘  └───────┼─────-┘  └──────────────────────-─┘
                            │
                            ▼
                    ┌───────────────┐     ┌───────────────┐
                    │ Wrapped       │     │ Public Key    │
                    │ Private Key   │     │ (X25519)      │
                    │ (ciphertext)  │     │ (plaintext)   │
                    │               │     │               │
                    │ STORED IN DB  │     │ STORED IN DB  │
                    └───────────────┘     └───────────────┘

  What's in the database:
  ───────────────────────
  ✓ Auth hash           — for login verification
  ✓ Wrapped private key — encrypted, useless without password
  ✓ Public key          — used to encrypt incoming mail
  ✓ Argon2 salt         — needed to re-derive keys on login
  ✓ Search key          — encrypted, useless without password

  What's NOT in the database:
  ────────────────────────────
  ✗ Password
  ✗ Master key
  ✗ Plaintext private key
  ✗ Encryption key
```

---

## 2. Receiving an Email — Encryption

When an email arrives (via SMTP or webmail compose), it's encrypted before touching disk.

```
  Incoming Email (plaintext)
  ┌─────────────────────────────┐
  │ From: alice@external.com    │
  │ To: bob@yourdomain.com      │
  │ Subject: Invoice #1234      │
  │                             │
  │ Hi Bob, here's the invoice  │
  │ for last month...           │
  └──────────────┬──────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────────────┐
  │  STEP 1: Generate random message key              │
  │                                                    │
  │  Message Key = random 256-bit AES key              │
  │  (unique per message — never reused)               │
  └──────────────────────┬─────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
  ┌─────────────────────┐  ┌────────────────────────────┐
  │  STEP 2: Encrypt     │  │  STEP 3: Wrap message key   │
  │  the email body      │  │  with recipient's public    │
  │                      │  │  key                        │
  │  AES-256-GCM(        │  │                             │
  │    plaintext,        │  │  ECDH(                      │
  │    message_key       │  │    sender_ephemeral_key,    │
  │  )                   │  │    bob_public_key           │
  │                      │  │  ) → shared_secret          │
  │  → body_ciphertext   │  │                             │
  │  → body_nonce        │  │  AES-256-GCM(               │
  │                      │  │    message_key,             │
  └──────────┬───────────┘  │    shared_secret            │
             │              │  )                           │
             │              │                             │
             │              │  → wrapped_key               │
             │              │  → key_nonce                 │
             │              └──────────────┬───────────────┘
             │                             │
             └──────────┬──────────────────┘
                        │
                        ▼
  ┌──────────────────────────────────────────────────────┐
  │              STORED IN SQLITE                         │
  │                                                       │
  │  ┌─────────────────┐  ┌──────────────────────┐       │
  │  │ body_enc         │  │ message_key_enc       │      │
  │  │ (ciphertext)     │  │ (wrapped key)         │      │
  │  │                  │  │                       │      │
  │  │ ░░░░░░░░░░░░░░░ │  │ ░░░░░░░░░░░░░░░░░░░░ │      │
  │  │ ░░░░░░░░░░░░░░░ │  │ ░░░░░░░░░░░░░░░░░░░░ │      │
  │  │ ░░░░░░░░░░░░░░░ │  │                       │      │
  │  └─────────────────┘  └──────────────────────-─┘      │
  │                                                       │
  │  + body_nonce              + key_nonce                 │
  │                                                       │
  │  ALL OPAQUE BINARY — no plaintext anywhere             │
  └───────────────────────────────────────────────────────┘

  If someone steals the database file, they see:
  ┌─────────────────────────────────────────────┐
  │  body_enc:  0x7a3f8b2c1d9e4f5a6b7c8d9e...   │
  │  key_enc:   0x2b4c6d8e0f1a2b3c4d5e6f7a...   │
  │  nonces:    0x1a2b3c4d5e6f7a8b9c0d1e2f...   │
  │                                               │
  │  Can they read "Invoice #1234"? NO.           │
  │  Can the server admin? NO.                    │
  │  Can law enforcement with disk access? NO.    │
  │                                               │
  │  Only Bob's password can unlock this.         │
  └─────────────────────────────────────────────-─┘
```

---

## 3. Reading an Email — Decryption

When Bob logs in and opens a message, the reverse happens — but only in memory.

```
  Bob types password
         │
         ▼
  ┌──────────────────────────────────────────┐
  │  ARGON2ID(password, stored_salt)          │
  │  → Master Key                             │
  │                                           │
  │  HKDF(master_key, "encrypt")              │
  │  → Encryption Key                         │
  │                                           │
  │  AES-GCM-Decrypt(                         │
  │    wrapped_private_key,                   │
  │    encryption_key                         │
  │  )                                        │
  │  → Bob's X25519 Private Key               │
  │                                           │
  │  ┌─────────────────────────────────────┐  │
  │  │  Private key held in memory         │  │
  │  │  for the duration of the session    │  │
  │  └─────────────────────────────────────┘  │
  └──────────────────────┬────────────────────┘
                         │
  Bob clicks a message   │
         │               │
         ▼               ▼
  ┌──────────────────────────────────────────┐
  │  STEP 1: Unwrap the message key           │
  │                                           │
  │  ECDH(                                    │
  │    bob_private_key,                       │
  │    sender_ephemeral_public_key            │
  │  ) → shared_secret                        │
  │                                           │
  │  AES-GCM-Decrypt(                         │
  │    wrapped_message_key,                   │
  │    shared_secret                          │
  │  ) → message_key                          │
  └──────────────────────┬────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────┐
  │  STEP 2: Decrypt the email body           │
  │                                           │
  │  AES-GCM-Decrypt(                         │
  │    body_ciphertext,                       │
  │    message_key                            │
  │  ) → plaintext email                      │
  └──────────────────────┬────────────────────┘
                         │
                         ▼
  ┌─────────────────────────────────────────┐
  │  From: alice@external.com               │
  │  Subject: Invoice #1234                 │
  │                                         │
  │  Hi Bob, here's the invoice             │
  │  for last month...                      │
  │                                         │
  │  ┌───────────────────────────────────┐  │
  │  │  Rendered in browser / IMAP       │  │
  │  │  NEVER written back to disk       │  │
  │  └───────────────────────────────────┘  │
  └─────────────────────────────────────────┘

  When Bob logs out:
  ┌─────────────────────────────────────────┐
  │                                         │
  │  crypto.Wipe(privateKey)                │
  │  crypto.Wipe(searchKey)                 │
  │  crypto.Wipe(encryptionKey)             │
  │                                         │
  │  All key material zeroed from memory.   │
  │  Session destroyed. Keys gone.          │
  │                                         │
  └─────────────────────────────────────────┘
```

---

## 4. Searching Email — Blind Index

How do you search encrypted email without decrypting everything? Blind indexing.

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    ON MESSAGE INGEST                          │
  └─────────────────────────────────────────────────────────────┘

  Plaintext email (before encryption):
  "Hi Bob, here's the invoice for last month"

         │
         ▼ Tokenize + normalize

  ["hi", "bob", "here", "invoice", "last", "month"]

         │
         ▼ HMAC-SHA256 each word with user's search key

  ┌───────────────┬──────────────────────────────────────────┐
  │ Word          │ HMAC-SHA256(search_key, word)             │
  ├───────────────┼──────────────────────────────────────────┤
  │ "hi"          │ 0xa3f8b2c1d9e4f5a6b7c8d9e0f1a2b3c4...   │
  │ "bob"         │ 0x7b4c6d8e0f1a2b3c4d5e6f7a8b9c0d1e...   │
  │ "invoice"     │ 0x2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b...   │
  │ "month"       │ 0x9c0d3e6f1a4b7c2d5e8f0a3b6c9d2e5f...   │
  │ ...           │ ...                                       │
  └───────────────┴──────────────────────────────────────────┘

         │
         ▼ Store in search_index table

  ┌────────────────────────────────────────────────────────────┐
  │  search_index table                                         │
  │                                                             │
  │  message_id │ token_hash                        │ field     │
  │  ───────────┼───────────────────────────────────┼────────── │
  │  42         │ 0xa3f8b2c1d9e4f5a6b7c8d9e0f1...  │ body      │
  │  42         │ 0x7b4c6d8e0f1a2b3c4d5e6f7a8b...  │ body      │
  │  42         │ 0x2e5f8a1b4c7d0e3f6a9b2c5d8e...  │ body      │
  │  42         │ 0x5d8e1f4a7b0c3d6e9f2a5b8c1d...  │ subject   │
  │  ...        │ ...                               │ ...       │
  └────────────────────────────────────────────────────────────┘

  The server stores HASHES, not words.
  It cannot reverse 0xa3f8b2... back to "hi".


  ┌─────────────────────────────────────────────────────────────┐
  │                    ON SEARCH QUERY                            │
  └─────────────────────────────────────────────────────────────┘

  Bob searches for "invoice"
         │
         ▼
  ┌──────────────────────────────────────────────────┐
  │  Client computes:                                 │
  │  HMAC-SHA256(search_key, "invoice")               │
  │  → 0x2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b...        │
  └──────────────────────┬────────────────────────────┘
                         │
                         ▼ Send hash to server
  ┌──────────────────────────────────────────────────┐
  │  Server matches hash against search_index:        │
  │                                                   │
  │  SELECT message_id                                │
  │  FROM search_index                                │
  │  WHERE token_hash = 0x2e5f8a1b4c7d0e3f...        │
  │                                                   │
  │  → message_id: 42                                 │
  │                                                   │
  │  Server knows: "message 42 matches"               │
  │  Server does NOT know: what was searched for       │
  └──────────────────────────────────────────────────-┘

  ┌──────────────────────────────────────────────────┐
  │                                                   │
  │  What the server sees during search:              │
  │                                                   │
  │    Query: 0x2e5f8a1b4c7d0e3f6a9b2c5d8e...       │
  │    Result: message IDs [42, 78, 103]              │
  │                                                   │
  │  What the server DOESN'T know:                    │
  │    - The search term ("invoice")                  │
  │    - The content of matching messages              │
  │    - Why those messages matched                    │
  │                                                   │
  └──────────────────────────────────────────────────-┘
```

---

## 5. Vault Password — Split-Key Architecture

GhostMail supports an enhanced security model where authentication and decryption use **separate passwords**. This is the default for accounts created via the provisioning API.

```
  ┌──────────────────────────────────────────────────────────────────┐
  │              TWO INDEPENDENT PASSWORDS                            │
  └──────────────────────────────────────────────────────────────────┘

  Auth Password                         Vault Password
  (proves identity)                     (unlocks decryption)
       │                                      │
       ▼                                      ▼
  ┌──────────────────┐                 ┌──────────────────┐
  │    ARGON2ID       │                 │    ARGON2ID       │
  │  (separate salt)  │                 │  (separate salt)  │
  └────────┬─────────┘                 └────────┬─────────┘
           │                                     │
     ┌─────┴─────┐                         ┌─────┴─────┐
     │           │                         │           │
     ▼           ▼                         ▼           ▼
  Auth Hash   Search Key              Vault Hash   Vault Key
  (stored)    (for HMAC index)        (stored)        │
                                                      ▼
                                               ┌─────────────┐
                                               │ AES-256-GCM  │
                                               │ unwrap X25519│
                                               │ private key  │
                                               └──────┬──────┘
                                                      │
                                                      ▼
                                               X25519 Private Key
                                               (held in RAM only)


  WHY SPLIT PASSWORDS?
  ────────────────────

  Single password model:
  ┌───────────────────────────────────────────────────────────────┐
  │  Login → password derives auth hash AND private key            │
  │  Risk: IMAP/SMTP client stores password → private key exposed  │
  └───────────────────────────────────────────────────────────────┘

  Split password model (vault):
  ┌───────────────────────────────────────────────────────────────┐
  │  Login → auth password proves identity only                    │
  │  Decrypt → vault password entered separately, on demand        │
  │                                                                │
  │  IMAP client stores auth password → can send/receive           │
  │  but CANNOT decrypt message bodies                             │
  │                                                                │
  │  Vault password entered conversationally via OpenClaw           │
  │  → held in RAM for 30 minutes → auto-wiped                    │
  │  → NEVER stored on disk, config, or env var                    │
  └───────────────────────────────────────────────────────────────┘


  VAULT SESSION LIFECYCLE
  ───────────────────────

  ┌──────────┐     POST /api/v1/auth/login     ┌──────────────┐
  │  Locked   │ ──────────────────────────────► │  Logged In    │
  │  (no keys │     (auth password only)        │  (can send,   │
  │  in RAM)  │                                 │  sees encrypted│
  └──────────┘                                  │  blobs only)  │
                                                └──────┬───────┘
                                                       │
                                  POST /api/v1/vault/unlock
                                  (vault password)
                                                       │
                                                       ▼
                                                ┌──────────────┐
                                                │  Vault Open   │
                                                │  (private key │
                                                │  in RAM,      │
                                                │  can decrypt)  │
                                                └──────┬───────┘
                                                       │
                                         30 min TTL or POST /vault/lock
                                                       │
                                                       ▼
                                                ┌──────────────┐
                                                │  Keys Wiped   │
                                                │  Back to       │
                                                │  Logged In     │
                                                └──────────────┘

  What's in the database (vault user):
  ─────────────────────────────────────
  ✓ Auth hash             — for login verification (from auth password)
  ✓ Vault hash            — for vault unlock verification (from vault password)
  ✓ Vault-wrapped privkey — X25519 private key encrypted by vault key
  ✓ Vault key nonce       — nonce for the wrapping
  ✓ Vault key params      — Argon2 params for vault password derivation
  ✓ Public key            — for encrypting incoming mail
  ✓ Search key            — for blind index (derived from auth password)

  What's NOT in the database:
  ────────────────────────────
  ✗ Auth password
  ✗ Vault password
  ✗ Plaintext private key
  ✗ Vault key (derived from vault password)
```

---

## 6. Full Lifecycle — End to End

```
          ALICE (external)                    GHOSTMAIL SERVER                         BOB (local user)
         ─────────────────                   ─────────────────                        ────────────────

         Composes email         SMTP :25
         "Hi Bob, invoice" ──────────────►  Lookup bob@domain
                                                    │
                                                    ▼
                                            Is Bob a local user? ──► YES
                                                    │
                                                    ▼
                                            Fetch Bob's X25519
                                            public key from DB
                                                    │
                                                    ▼
                                            ┌─────────────────┐
                                            │ ENCRYPT:         │
                                            │                  │
                                            │ 1. Random AES    │
                                            │    message key   │
                                            │                  │
                                            │ 2. AES-GCM       │
                                            │    encrypt body   │
                                            │                  │
                                            │ 3. X25519+AES    │
                                            │    wrap msg key   │
                                            │    with Bob's     │
                                            │    public key     │
                                            └────────┬────────┘
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │ STORE:           │
                                            │ body_enc (blob)  │
                                            │ key_enc (blob)   │
                                            │ nonces           │
                                            └─────────────────┘
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │ INDEX:           │
                                            │ HMAC each word   │
                                            │ with Bob's       │
                                            │ search key       │
                                            │ Store hashes     │
                                            └─────────────────┘
                                                     │
                                            ─ ─ ─ ─ ─ ─ ─ ─ ─ ─    (time passes)
                                                     │
                                                                       Bob opens browser
                                                                       goes to /mail/
                                                                              │
                                                                              ▼
                                                                       Types password
                                                                              │
                                            ◄──────────────────────────────────
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │ LOGIN:           │
                                            │ Argon2id(pass)   │
                                            │ → master key     │
                                            │ → auth hash      │
                                            │ Verify auth hash │
                                            │ ✓ Match!        │
                                            │                  │
                                            │ Unwrap private   │
                                            │ key into memory  │
                                            └────────┬────────┘
                                                     │
                                                     ▼
                                            Keys held in server ──────────────►  Bob sees inbox:
                                            memory (RAM only)                    "1 new message"
                                                     │                                  │
                                                     │                           Bob clicks message
                                                     │                                  │
                                            ◄────────────────────────────────────────────
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │ DECRYPT:         │
                                            │                  │
                                            │ 1. ECDH with     │
                                            │    Bob's privkey  │
                                            │    → shared       │
                                            │    secret        │
                                            │                  │
                                            │ 2. Unwrap msg    │
                                            │    key           │
                                            │                  │
                                            │ 3. AES-GCM       │
                                            │    decrypt body   │
                                            └────────┬────────┘
                                                     │
                                                     ▼
                                            Plaintext in memory ──────────────►  Bob reads:
                                            (never saved to disk)                "Hi Bob, invoice"
                                                     │
                                            ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
                                                     │
                                                                       Bob clicks Logout
                                                                              │
                                            ◄──────────────────────────────────
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │ WIPE:            │
                                            │ Zero private key │
                                            │ Zero search key  │
                                            │ Zero session     │
                                            │ Keys GONE        │
                                            └─────────────────┘

                                            Database still contains
                                            only ciphertext.
                                            No keys in memory.
                                            Server is "zero-knowledge"
                                            again.
```

---

## What Each Layer Protects Against

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │   THREAT                          PROTECTION                     │
  │   ──────                          ──────────                     │
  │                                                                  │
  │   Network sniffing                TLS 1.3 on all connections     │
  │   (WiFi, ISP, backbone)          (SMTP, IMAP, HTTPS)            │
  │                                                                  │
  │   ─────────────────────────────────────────────────────────────  │
  │                                                                  │
  │   Server compromise              Per-message envelope encryption │
  │   (hacker gets root)             (X25519 + AES-256-GCM)         │
  │                                  Private keys wrapped, need      │
  │                                  user's password to unwrap       │
  │                                                                  │
  │   ─────────────────────────────────────────────────────────────  │
  │                                                                  │
  │   Rogue server admin             Zero-knowledge architecture     │
  │   (insider threat)               Admin has access to database    │
  │                                  but only sees ciphertext.       │
  │                                  No password = no decryption.    │
  │                                                                  │
  │   ─────────────────────────────────────────────────────────────  │
  │                                                                  │
  │   Disk theft / backup leak       All data encrypted at rest      │
  │   (physical access)              SQLite contains only blobs      │
  │                                                                  │
  │   ─────────────────────────────────────────────────────────────  │
  │                                                                  │
  │   Email spoofing                 DKIM signing (RSA-2048/Ed25519) │
  │   (someone fakes From:)         SPF + DMARC enforcement          │
  │                                                                  │
  │   ─────────────────────────────────────────────────────────────  │
  │                                                                  │
  │   Metadata leakage               Received headers stripped       │
  │   (who sent from where)         User-Agent stripped              │
  │                                  X-Originating-IP stripped       │
  │                                  IP logging disabled by default  │
  │                                                                  │
  │   ─────────────────────────────────────────────────────────────  │
  │                                                                  │
  │   Search query surveillance      Blind HMAC-SHA256 index         │
  │   (admin sees what you search)  Server matches hashes, not words │
  │                                                                  │
  │   ─────────────────────────────────────────────────────────────  │
  │                                                                  │
  │   Password brute force           Argon2id (64MB memory, 3 iter)  │
  │   (offline attack on hash)      ~$10M+ to crack a single hash   │
  │                                                                  │
  │   ─────────────────────────────────────────────────────────────  │
  │                                                                  │
  │   Session hijacking              Keys wiped on logout/expiry     │
  │   (stolen session cookie)       4-hour max TTL, background sweep │
  │                                                                  │
  └─────────────────────────────────────────────────────────────────┘
```

---

## Algorithms Used

```
  ┌──────────────────────┬─────────────────────────────────┐
  │  Purpose             │  Algorithm                       │
  ├──────────────────────┼─────────────────────────────────┤
  │  Password hashing    │  Argon2id (t=3, m=64MB, p=4)    │
  │  Key derivation      │  HKDF-SHA256                     │
  │  Key exchange        │  X25519 (Curve25519 ECDH)        │
  │  Message encryption  │  AES-256-GCM                     │
  │  Key wrapping        │  AES-256-GCM                     │
  │  Search index        │  HMAC-SHA256                     │
  │  DKIM signing        │  RSA-2048 or Ed25519             │
  │  Transport           │  TLS 1.3                         │
  │  External encrypt    │  OpenPGP (optional, per-contact) │
  │  Memory safety       │  Explicit zero-fill on logout    │
  └──────────────────────┴─────────────────────────────────┘
```
