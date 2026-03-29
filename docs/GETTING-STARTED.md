# Getting Started with GhostMail

So you want your own email server. Not Gmail. Not Outlook. Yours.

GhostMail gives you a private email address on your own domain — and unlike every other self-hosted mail server, your emails are actually encrypted. Not just "encrypted in transit." Encrypted so that even if someone steals the hard drive, they get nothing.

This guide walks you through the whole thing. No sysadmin experience required.

---

## What You'll End Up With

- Your own email address: `you@yourdomain.com`
- A webmail interface you access in your browser (like Gmail, but private)
- Works with Thunderbird, Apple Mail, or any email app
- Disposable aliases for signing up to sketchy websites
- Everything encrypted — your emails are unreadable without your password

---

## What You'll Need

**Option 1: You have a server** (VPS, Mac Mini, old laptop, Raspberry Pi)
- A computer that stays on 24/7 with an internet connection
- A domain name ($10-15/year from Namecheap, Cloudflare, or Porkbun)
- 15 minutes

**Option 2: You don't have anything yet**
- A $5/month VPS from DigitalOcean, Hetzner, or Vultr
- A domain name
- 15 minutes

**Option 3: You just want to try it**
- Nothing. You can get an instant email address without a domain or server.

---

## Option 3: Instant Email (Easiest)

If someone is running a GhostMail instance with subdomain support, you can get an email address in seconds:

```bash
ghostctl subdomain create -parent ghostmail.dev
```

You'll get something like `admin@a1b2c3.ghostmail.dev` — a real, working email address. No domain purchase, no DNS, no server setup. Start sending and receiving immediately.

Want your own domain later? You can add one anytime.

---

## Option 1 & 2: Your Own Server

### Step 1: Get a Server

If you don't have one, sign up for a VPS:

- **DigitalOcean**: Create a Droplet ($6/month, Ubuntu 24.04)
- **Hetzner**: Create a server ($4/month, best value)
- **Vultr**: Create an instance ($5/month)

Pick the smallest size. GhostMail runs on 256MB of RAM.

Once it's running, note your server's **IP address** (looks like `123.45.67.89`).

### Step 2: Get a Domain

Buy a domain from any registrar:

- **Cloudflare** (recommended — free DNS, GhostMail can auto-configure it)
- **Namecheap** ($8-12/year for a .com)
- **Porkbun** (cheap and good)

### Step 3: Install GhostMail

SSH into your server and run one command:

```bash
curl -fsSL https://raw.githubusercontent.com/bigdestiny2/ghostmail/main/install.sh | sh
```

It'll ask for your domain name, then:
1. Installs Docker (if needed)
2. Deploys GhostMail
3. Sets up HTTPS automatically
4. Creates your admin account
5. Prints your password and DNS records

Save the password it gives you!

### Step 4: Set Up DNS

This is the part that connects your domain to your server. You need to add some records at your domain registrar.

**If your domain is on Cloudflare** (auto mode):

```bash
# SSH into your server, then:
docker exec ghostmail ghostctl dns setup -domain yourdomain.com -provider cloudflare -api-key YOUR_CF_TOKEN
```

Done. All records created automatically.

**If your domain is elsewhere** (manual mode):

Go to your registrar's DNS settings and add these records:

| Type | Name | Value |
|------|------|-------|
| A | `mail.yourdomain.com` | `your-server-ip` |
| MX | `yourdomain.com` | `mail.yourdomain.com` (priority 10) |
| TXT | `yourdomain.com` | `v=spf1 mx a -all` |
| TXT | `_dmarc.yourdomain.com` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s` |

Then get your DKIM record:

```bash
docker exec ghostmail ghostctl dkim dns -domain yourdomain.com
```

Add that TXT record too.

### Step 5: Wait 10 Minutes

DNS records take a few minutes to kick in. You can check:

```bash
docker exec ghostmail ghostctl dns verify -domain yourdomain.com
```

When everything says PASS, you're live.

### Step 6: Log In

Open your browser and go to:

```
https://mail.yourdomain.com/mail/
```

Log in with your admin email and the password from Step 3. You're done.

---

## Using Your Mac Mini as a Mail Server

If you have a Mac Mini (or any Mac) sitting around:

```bash
curl -fsSL https://raw.githubusercontent.com/bigdestiny2/ghostmail/main/deploy/macos/install-macos.sh | bash
```

This installs GhostMail natively (no Docker needed) and sets it up as a system service that starts automatically when your Mac boots. Everything else is the same — do Steps 2 and 4 above for domain and DNS.

**Important for home servers:** Your ISP probably blocks port 25 (the mail port). You may need to:
- Call your ISP and ask them to unblock port 25
- Or use a VPS instead (port 25 is open by default on VPS providers)

---

## Using GhostMail with an AI Agent

If you're running OpenClaw or Hermes Agent, your AI can deploy and manage your email:

```bash
# Install the skills
npx clawhub install ghostmail-deploy
npx clawhub install ghostmail-email
```

Then just tell your agent:
- "Deploy my email server for mydomain.com"
- "Check my inbox"
- "Send an email to alice@example.com about the project update"
- "Create a throwaway email for this newsletter signup"

Your AI handles everything through GhostMail's API.

---

## Day-to-Day Usage

### Webmail

Go to `https://mail.yourdomain.com/mail/` in any browser. It works like Gmail:

- **Left sidebar**: Your folders (Inbox, Sent, Drafts, Trash, Spam) and aliases
- **Middle column**: Message list
- **Right panel**: Read messages

Click **Compose** to write an email. Hit **Ctrl+Enter** to send.

### Email Apps

You can also use any email app (Thunderbird, Apple Mail, iPhone Mail, etc.):

| Setting | Value |
|---------|-------|
| IMAP Server | `mail.yourdomain.com` |
| IMAP Port | `993` (SSL/TLS) |
| SMTP Server | `mail.yourdomain.com` |
| SMTP Port | `587` (STARTTLS) |
| Username | `you@yourdomain.com` |
| Password | Your password |

### Disposable Aliases

Signing up for something and don't want to give your real email? Create a disposable alias:

1. In webmail, click **+ New Alias** in the sidebar
2. You get a random address like `xk9qm2wf@yourdomain.com`
3. Use that for the signup
4. All mail to that alias goes to your real inbox
5. Getting spam? Delete the alias. Done.

You can have up to 50 aliases.

### Searching

Type in the search bar at the top. GhostMail finds matching messages.

Behind the scenes, this search is privacy-preserving — the server doesn't know what you searched for. It works on individual words, so search for "invoice" or "meeting" rather than exact phrases.

---

## Adding More Users

Want email for your family or team?

**Via the admin panel:**
Go to `https://mail.yourdomain.com/admin/` and click "Create User."

**Via command line:**
```bash
docker exec ghostmail ghostctl user create \
  -username alice \
  -domain yourdomain.com \
  -password their-password
```

Each user gets their own encryption keys. You (the admin) cannot read their mail. That's the point.

---

## Frequently Asked Questions

**Is my email really private?**
Yes. Each email is encrypted with the recipient's public key before being saved. The encryption key is wrapped with a key derived from your password. Without the password, the emails are unreadable — even to someone with full access to the server and database.

**Can I move from Gmail?**
Yes. Set up GhostMail, then update your important accounts to use your new email. You can forward Gmail to your new address during the transition. There's no automated import tool yet — that's planned.

**Will my emails go to spam?**
They shouldn't, if you set up DNS correctly. GhostMail signs outgoing mail with DKIM and includes SPF/DMARC records. Run `ghostctl dns verify` to confirm everything is set up right. New domains sometimes have a warm-up period — send to contacts first before mass-mailing.

**What if I forget my password?**
There is no password reset. This is by design — if there were, someone else could reset it too. Your password is the root of all encryption. Forget it and your emails are permanently unreadable. Write it down and keep it somewhere safe.

**What if the server dies?**
Your email data is in `/var/lib/ghostmail/`. Back up that directory regularly. If you restore it to a new server, everything works — but you still need your password to read the emails.

**How much storage do I need?**
A typical email is a few KB. Even with attachments, 10GB gets you thousands of emails. The $5 VPS options come with 25-50GB, which is plenty.

**Can I use a custom domain email for free?**
The software is free. You'll pay for the domain ($10-15/year) and the server ($4-6/month). That's roughly $60-85/year total — about the same as a Proton Mail Plus subscription, but you own everything.

---

## Troubleshooting

**Can't connect to webmail:**
```bash
# Check if GhostMail is running
docker compose -f ~/ghostmail/docker-compose.yml ps

# View logs
docker compose -f ~/ghostmail/docker-compose.yml logs ghostmail
```

**Emails aren't being received:**
```bash
# Verify DNS records
docker exec ghostmail ghostctl dns verify -domain yourdomain.com
```

If MX or A records show FAIL, check your DNS settings and wait for propagation.

**Emails going to spam:**
Make sure SPF, DKIM, and DMARC records are all set up. New domains need a few days to build reputation — send to people you know first.

**Port 25 blocked:**
Common on home internet. Check with `telnet mail.yourdomain.com 25`. If it times out, your ISP is blocking it. Use a VPS instead, or ask your ISP to unblock.

---

## Useful Commands

```bash
# Check server health
curl http://localhost:8080/health

# View logs
docker compose -f ~/ghostmail/docker-compose.yml logs -f

# Create a new user
docker exec ghostmail ghostctl user create -username bob -domain yourdomain.com -password secret

# List all users
docker exec ghostmail ghostctl user list

# Generate DKIM keys
docker exec ghostmail ghostctl dkim generate -domain yourdomain.com

# Check DNS
docker exec ghostmail ghostctl dns verify -domain yourdomain.com

# Update to latest version
cd ~/ghostmail && docker compose pull && docker compose up -d

# Backup your data
docker cp ghostmail:/var/lib/ghostmail ./ghostmail-backup-$(date +%Y%m%d)
```

---

That's it. You now have a private, encrypted email system that you fully control. No company scanning your emails for ads, no government quietly requesting your inbox, no third party holding your keys. Just you and your mail.
