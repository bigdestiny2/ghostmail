// GhostBot — GhostMail Telegram bot for identity purchases and onboarding.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Config holds bot configuration loaded from environment variables.
type Config struct {
	TelegramToken string // GHOSTBOT_TELEGRAM_TOKEN
	APIBaseURL    string // GHOSTBOT_API_URL (e.g. https://mail.ghostmail.llc:8443)
	OnionAddress  string // GHOSTBOT_ONION_ADDRESS
	KeetRoomLink  string // GHOSTBOT_KEET_ROOM (invite link)
	Domain        string // GHOSTBOT_DOMAIN (e.g. ghostmail.llc)
	HolesailKey   string // GHOSTBOT_HOLESAIL_KEY (connection string)
}

// pendingOrder tracks a user's in-progress signup.
type pendingOrder struct {
	Username string
	Chain    string
	Created  time.Time
}

var (
	cfg Config
	// Telegram API client (normal TLS)
	tgClient = &http.Client{Timeout: 60 * time.Second}
	// GhostMail API client (skip TLS verify for localhost self-signed cert)
	apiClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	orderMu sync.Mutex
	orders  = make(map[int64]*pendingOrder) // chatID -> order
)

func main() {
	cfg = Config{
		TelegramToken: os.Getenv("GHOSTBOT_TELEGRAM_TOKEN"),
		APIBaseURL:    os.Getenv("GHOSTBOT_API_URL"),
		OnionAddress:  os.Getenv("GHOSTBOT_ONION_ADDRESS"),
		Domain:        os.Getenv("GHOSTBOT_DOMAIN"),
		KeetRoomLink:  os.Getenv("GHOSTBOT_KEET_ROOM"),
		HolesailKey:   os.Getenv("GHOSTBOT_HOLESAIL_KEY"),
	}
	if cfg.TelegramToken == "" {
		log.Fatal("GHOSTBOT_TELEGRAM_TOKEN is required")
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = "https://mail.ghostmail.llc:8443"
	}
	if cfg.Domain == "" {
		cfg.Domain = "ghostmail.llc"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
	}()

	log.Println("GhostBot starting...")
	pollUpdates(ctx)
}

// --- Telegram API types ---

type Update struct {
	UpdateID int      `json:"update_id"`
	Message  *Message `json:"message,omitempty"`
}

type Message struct {
	MessageID int    `json:"message_id"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
	From      *User  `json:"from,omitempty"`
}

type Chat struct {
	ID int64 `json:"id"`
}

type User struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

// --- Polling loop ---

func pollUpdates(ctx context.Context) {
	offset := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=30", cfg.TelegramToken, offset)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := tgClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("poll error: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		var result struct {
			OK     bool     `json:"ok"`
			Result []Update `json:"result"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		for _, u := range result.Result {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			if u.Message != nil && u.Message.Text != "" {
				handleMessage(u.Message)
			}
		}
	}
}

// --- Message router ---

func handleMessage(m *Message) {
	text := strings.TrimSpace(m.Text)
	switch {
	case text == "/start":
		cmdStart(m)
	case text == "/buy":
		cmdBuy(m)
	case text == "/access":
		cmdAccess(m)
	case text == "/keet":
		cmdKeet(m)
	case text == "/holesail":
		cmdHolesail(m)
	case text == "/help":
		cmdHelp(m)
	case text == "/status":
		cmdStatus(m)
	case strings.HasPrefix(text, "/chain "):
		cmdChain(m, strings.TrimPrefix(text, "/chain "))
	case strings.HasPrefix(text, "/username "):
		cmdUsername(m, strings.TrimPrefix(text, "/username "))
	case strings.HasPrefix(text, "/pay "):
		cmdPay(m, strings.TrimPrefix(text, "/pay "))
	default:
		// Ignore non-command messages
	}
}

// --- Command handlers ---

func cmdStart(m *Message) {
	name := "there"
	if m.From != nil && m.From.FirstName != "" {
		name = escHTML(m.From.FirstName)
	}
	send(m.Chat.ID, fmt.Sprintf(`👻 <b>Welcome to GhostMail, %s!</b>

GhostMail is an encrypted, privacy-first email service accessible exclusively through the Tor network.

🔐 End-to-end encrypted inbox
🧅 Tor-only webmail access
💬 Keet P2P encrypted chat
💰 $10 one-time payment to secure your @ghostmail.llc email and handle — yours forever, no subscriptions

<b>Commands:</b>
/buy — Purchase your GhostMail identity
/access — Get Tor onion link &amp; setup info
/keet — Join our Keet chat community
/holesail — P2P tunnel access (no Tor needed)
/help — Show all commands`, name))
}

func cmdHelp(m *Message) {
	send(m.Chat.ID, `📖 <b>GhostBot Commands</b>

/start — Welcome message
/buy — Start purchasing a GhostMail identity
/access — Get Tor links &amp; connection info
/keet — Keet encrypted chat info &amp; invite
/holesail — P2P tunnel access (no Tor needed)
/status — Check provisioning service status

<b>Purchase flow:</b>
/buy → /username &lt;name&gt; → /chain &lt;eth|base|bsc|solana&gt; → send crypto → /pay &lt;tx_hash&gt;`)
}

func cmdBuy(m *Message) {
	info, err := fetchProvisionStatus()
	if err != nil {
		send(m.Chat.ID, "⚠️ Service temporarily unavailable. Try again shortly.")
		log.Printf("provision status error: %v", err)
		return
	}

	var chains strings.Builder
	for _, c := range info.Chains {
		chains.WriteString(fmt.Sprintf("\n<code>%s</code> — <code>%s</code>", strings.ToUpper(c.Chain), c.Address))
	}

	send(m.Chat.ID, fmt.Sprintf(`🛒 <b>Purchase GhostMail Identity</b>

<b>Price:</b> $%.0f USD (one-time)
<b>Domain:</b> %s
<b>Storage:</b> %dMB encrypted inbox

<b>Accepted chains:</b>%s

<b>Step 1:</b> Choose your username
/username &lt;your_name&gt;

<i>Username rules: 3-32 chars, lowercase, letters/numbers/.-_</i>`, info.PriceUSD, escHTML(info.Domain), info.QuotaMB, chains.String()))
}

func cmdUsername(m *Message, username string) {
	username = strings.TrimSpace(strings.ToLower(username))

	if !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`).MatchString(username) {
		send(m.Chat.ID, "❌ Invalid username. Must be 3-32 chars, start with letter/number, only <code>a-z 0-9 . _ -</code>")
		return
	}

	reserved := map[string]bool{
		"admin": true, "postmaster": true, "hostmaster": true, "abuse": true,
		"webmaster": true, "root": true, "info": true, "support": true,
		"noreply": true, "mailer-daemon": true, "security": true,
	}
	if reserved[username] {
		send(m.Chat.ID, "❌ That username is reserved. Choose another.")
		return
	}

	orderMu.Lock()
	orders[m.Chat.ID] = &pendingOrder{Username: username, Created: time.Now()}
	orderMu.Unlock()

	send(m.Chat.ID, fmt.Sprintf(`✅ Username: <b>%s</b>@%s

<b>Step 2:</b> Choose your payment chain
/chain eth
/chain base
/chain bsc
/chain solana`, escHTML(username), escHTML(cfg.Domain)))
}

func cmdChain(m *Message, chain string) {
	chain = strings.TrimSpace(strings.ToLower(chain))
	valid := map[string]bool{"eth": true, "base": true, "bsc": true, "solana": true}
	if !valid[chain] {
		send(m.Chat.ID, "❌ Invalid chain. Choose: <code>eth</code>, <code>base</code>, <code>bsc</code>, or <code>solana</code>")
		return
	}

	orderMu.Lock()
	order := orders[m.Chat.ID]
	if order == nil {
		orderMu.Unlock()
		send(m.Chat.ID, "⚠️ Start with /username first.")
		return
	}
	order.Chain = chain
	orderMu.Unlock()

	info, err := fetchProvisionStatus()
	if err != nil {
		send(m.Chat.ID, "⚠️ Service unavailable. Try again.")
		return
	}

	var wallet string
	for _, c := range info.Chains {
		if c.Chain == chain {
			wallet = c.Address
			break
		}
	}

	send(m.Chat.ID, fmt.Sprintf(`💳 <b>Send $%.0f in %s to:</b>

<code>%s</code>

⚠️ Send <b>exactly $%.0f or more</b> in a single transaction.
15%% slippage tolerance for price fluctuations.

After sending, submit your transaction hash:
/pay &lt;tx_hash&gt;

<i>Your order expires in 1 hour.</i>`, info.PriceUSD, strings.ToUpper(chain), wallet, info.PriceUSD))
}

func cmdPay(m *Message, txHash string) {
	txHash = strings.TrimSpace(txHash)
	if txHash == "" {
		send(m.Chat.ID, "❌ Provide your transaction hash: <code>/pay 0xabc123...</code>")
		return
	}

	orderMu.Lock()
	order := orders[m.Chat.ID]
	if order == nil || order.Chain == "" {
		orderMu.Unlock()
		send(m.Chat.ID, "⚠️ No pending order. Start with /buy")
		return
	}
	if time.Since(order.Created) > time.Hour {
		delete(orders, m.Chat.ID)
		orderMu.Unlock()
		send(m.Chat.ID, "⏰ Order expired. Please start again with /buy")
		return
	}
	username := order.Username
	chain := order.Chain
	orderMu.Unlock()

	send(m.Chat.ID, "⏳ Verifying payment and creating your account...")

	authPass := generatePassword()
	vaultPass := generatePassword()

	result, err := provisionAccount(username, authPass, vaultPass, txHash, chain)
	if err != nil {
		send(m.Chat.ID, fmt.Sprintf("❌ <b>Signup failed:</b> %s\n\nIf your payment was valid, try again in a few minutes. Blockchain confirmations may be pending.", escHTML(err.Error())))
		return
	}

	orderMu.Lock()
	delete(orders, m.Chat.ID)
	orderMu.Unlock()

	send(m.Chat.ID, fmt.Sprintf(`✅ <b>Account Created!</b>

📧 <b>Email:</b> <code>%s</code>
🔑 <b>Auth Password:</b> <code>%s</code>
🔐 <b>Vault Password:</b> <code>%s</code>

📥 <b>IMAP:</b> <code>%s</code>
📤 <b>SMTP:</b> <code>%s</code>

🧅 <b>Webmail:</b> Access via Tor Browser at
<code>%s</code>

⚠️ <b>SAVE THESE PASSWORDS NOW</b>
<i>Delete this message after saving. Auth password is for email login. Vault password unlocks your encrypted messages.</i>

/access — Full setup guide
/keet — Join the community chat`, result.Email, authPass, vaultPass, result.IMAP, result.SMTP, "http://"+cfg.OnionAddress+"/mail/login"))
}

func cmdAccess(m *Message) {
	onion := cfg.OnionAddress
	if onion == "" {
		onion = "not configured"
	}

	send(m.Chat.ID, fmt.Sprintf(`🧅 <b>GhostMail Access Guide</b>

<b>1.</b> Download Tor Browser
https://www.torproject.org/download/

<b>2.</b> Open Webmail
<code>http://%s/mail/login</code>

<b>3.</b> Email Client Setup (optional)
IMAP: <code>mail.%s:993</code> (TLS)
SMTP: <code>mail.%s:465</code> (TLS)

<b>4.</b> Keet Encrypted Chat
/keet for invite link &amp; download

<b>5.</b> Holesail P2P Tunnel (alternative to Tor)
/holesail for connection key &amp; setup

<i>All access methods are end-to-end encrypted. Your IP is never exposed.</i>`, onion, cfg.Domain, cfg.Domain))
}

func cmdKeet(m *Message) {
	room := cfg.KeetRoomLink

	if room == "" {
		send(m.Chat.ID, `💬 <b>Keet — GhostMail Community Chat</b>

Keet is a peer-to-peer encrypted messenger. No servers, no metadata, no tracking.

<b>Download Keet:</b>
📱 iOS: App Store → search "Keet"
📱 Android: Play Store → search "Keet"
💻 Desktop: https://keet.io/

<i>Room invite coming soon.</i>`)
		return
	}

	send(m.Chat.ID, fmt.Sprintf(`💬 <b>Keet — GhostMail Community Chat</b>

Keet is a peer-to-peer encrypted messenger. No servers, no metadata, no tracking.

<b>Download Keet:</b>
📱 iOS: App Store → search "Keet"
📱 Android: Play Store → search "Keet"
💻 Desktop: https://keet.io/

<b>Join GhostMail Room:</b>
<code>%s</code>

<i>All messages are end-to-end encrypted and P2P. Not even GhostMail can read them.</i>`, room))

	sendQR(m.Chat.ID, room, "Scan with Keet to join GhostMail chat")
}

func cmdHolesail(m *Message) {
	key := cfg.HolesailKey
	if key == "" {
		send(m.Chat.ID, "⚠️ Holesail tunnel not configured yet.")
		return
	}

	send(m.Chat.ID, fmt.Sprintf(`⛵ <b>Holesail — P2P Tunnel Access</b>

Access GhostMail webmail via encrypted P2P tunnel — no Tor Browser needed.

<b>1.</b> Install Holesail
<code>npm i -g holesail</code>

<b>2.</b> Connect to GhostMail
<code>holesail %s</code>

<b>3.</b> Open in your browser
<code>http://localhost:8080/mail/login</code>

<b>How it works:</b>
Holesail creates a direct encrypted P2P tunnel from your machine to GhostMail using HyperDHT. No servers in between, no DNS, no port forwarding needed.

⚠️ <b>Keep your connection key private</b> — treat it like an SSH key.

<i>End-to-end encrypted. Zero-knowledge. No logs.</i>`, key))

	sendQR(m.Chat.ID, key, "Scan or copy to connect via Holesail")
}

func cmdStatus(m *Message) {
	info, err := fetchProvisionStatus()
	if err != nil {
		send(m.Chat.ID, fmt.Sprintf("🔴 Provisioning service offline: %s", escHTML(err.Error())))
		return
	}

	status := "🟢 Online"
	if !info.Available {
		status = "🔴 Unavailable"
	}

	send(m.Chat.ID, fmt.Sprintf(`📊 <b>GhostMail Status</b>

<b>Service:</b> %s
<b>Domain:</b> %s
<b>Price:</b> $%.0f
<b>Storage:</b> %dMB per account`, status, escHTML(info.Domain), info.PriceUSD, info.QuotaMB))
}

// --- Provisioning API client ---

type provisionStatus struct {
	Available bool    `json:"available"`
	Domain    string  `json:"domain"`
	PriceUSD  float64 `json:"price_usd"`
	QuotaMB   int     `json:"quota_mb"`
	Chains    []struct {
		Chain   string `json:"chain"`
		Address string `json:"address"`
	} `json:"chains"`
	IMAP string `json:"imap"`
	SMTP string `json:"smtp"`
}

type signupResult struct {
	OK    bool   `json:"ok"`
	Email string `json:"email"`
	IMAP  string `json:"imap"`
	SMTP  string `json:"smtp"`
	Error string `json:"error"`
}

func fetchProvisionStatus() (*provisionStatus, error) {
	resp, err := apiClient.Get(cfg.APIBaseURL + "/api/v1/provision/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var s provisionStatus
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

func provisionAccount(username, authPass, vaultPass, txHash, chain string) (*signupResult, error) {
	body, _ := json.Marshal(map[string]string{
		"username":       username,
		"auth_password":  authPass,
		"vault_password": vaultPass,
		"tx_hash":        txHash,
		"chain":          chain,
	})

	resp, err := apiClient.Post(cfg.APIBaseURL+"/api/v1/provision/signup", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("connection failed")
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result signupResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid response")
	}
	if !result.OK {
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return nil, fmt.Errorf("signup failed (HTTP %d)", resp.StatusCode)
	}
	return &result, nil
}

// --- Telegram helpers ---

func send(chatID int64, text string) {
	body, _ := json.Marshal(map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	})
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.TelegramToken)
	resp, err := tgClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("send error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		log.Printf("telegram error %d: %s\nmessage was: %s", resp.StatusCode, string(data), text)
	}
}

// sendQR generates a QR code PNG and sends it as a photo via Telegram.
func sendQR(chatID int64, data string, caption string) {
	png, err := qrcode.Encode(data, qrcode.Medium, 512)
	if err != nil {
		log.Printf("QR generation error: %v", err)
		return
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("chat_id", fmt.Sprintf("%d", chatID))
	w.WriteField("caption", caption)

	part, err := w.CreateFormFile("photo", "keet-invite.png")
	if err != nil {
		log.Printf("multipart error: %v", err)
		return
	}
	part.Write(png)
	w.Close()

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendPhoto", cfg.TelegramToken)
	resp, err := tgClient.Post(url, w.FormDataContentType(), &buf)
	if err != nil {
		log.Printf("sendQR error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("sendQR telegram error %d: %s", resp.StatusCode, string(body))
	}
}

// escHTML escapes special characters for Telegram HTML parse mode.
func escHTML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;",
	)
	return replacer.Replace(s)
}

// generatePassword creates a random 20-char password with upper, lower, digits.
func generatePassword() string {
	const (
		upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower  = "abcdefghijklmnopqrstuvwxyz"
		digits = "0123456789"
		all    = upper + lower + digits
	)

	b := make([]byte, 20)
	// Read from crypto/rand
	f, _ := os.Open("/dev/urandom")
	f.Read(b)
	f.Close()

	// Ensure at least one of each required class
	result := make([]byte, 20)
	result[0] = upper[int(b[0])%len(upper)]
	result[1] = lower[int(b[1])%len(lower)]
	result[2] = digits[int(b[2])%len(digits)]
	for i := 3; i < 20; i++ {
		result[i] = all[int(b[i])%len(all)]
	}

	// Shuffle
	for i := len(result) - 1; i > 0; i-- {
		j := int(b[i%len(b)]) % (i + 1)
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}
