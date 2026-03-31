// Package provisioning provides self-service account creation with crypto payments.
package provisioning

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/ratelimit"
	"github.com/ghostmail/ghostmail/internal/storage"
	"github.com/ghostmail/ghostmail/internal/vault"
)

var usernameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

var reservedNames = map[string]bool{
	"admin": true, "postmaster": true, "hostmaster": true,
	"abuse": true, "webmaster": true, "root": true,
	"info": true, "support": true, "noreply": true,
	"mailer-daemon": true, "security": true,
}

// API handles self-service account provisioning.
type API struct {
	cfg        *config.Config
	db         *storage.DB
	cryptoSvc  *crypto.Service
	vaultStore *vault.Store
	logger     *slog.Logger
	verifier   *PaymentVerifier
	limiter    *ratelimit.Limiter
}

// NewAPI creates a new provisioning API handler.
func NewAPI(cfg *config.Config, db *storage.DB, cryptoSvc *crypto.Service, vaultStore *vault.Store, logger *slog.Logger) *API {
	return &API{
		cfg:        cfg,
		db:         db,
		cryptoSvc:  cryptoSvc,
		vaultStore: vaultStore,
		logger:     logger,
		verifier:   NewPaymentVerifier(db, cfg, logger),
		limiter:    ratelimit.New(5, 5, time.Hour), // 5 requests/hour per IP
	}
}

// Register attaches provisioning routes to an HTTP mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/provision/status", a.handleStatus)
	mux.HandleFunc("POST /api/v1/provision/signup", a.handleSignup)
	mux.HandleFunc("GET /api/v1/provision/verify/{tx}", a.handleVerify)
}

// RunPaymentVerifier starts the background payment verification loop.
func (a *API) RunPaymentVerifier(ctx context.Context) {
	a.verifier.RunVerifier(ctx)
}

type chainWallet struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

type statusResponse struct {
	Available bool          `json:"available"`
	Domain    string        `json:"domain"`
	PriceUSD  float64       `json:"price_usd"`
	QuotaMB   int64         `json:"quota_mb"`
	Chains    []chainWallet `json:"chains"`
	IMAP      string        `json:"imap"`
	SMTP      string        `json:"smtp"`
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Rate limit: shared with signup, 5 requests per hour per IP.
	// X-Forwarded-For is ignored (no trusted proxy config); trusting it
	// would allow clients to spoof their IP for rate-limit bypass.
	ip := strings.TrimSpace(r.RemoteAddr)
	if !a.limiter.Allow(ip) {
		jsonError(w, "too many requests, try again later", http.StatusTooManyRequests)
		return
	}

	var wallets []chainWallet
	for _, chain := range a.verifier.SupportedChains() {
		wallets = append(wallets, chainWallet{
			Chain:   chain,
			Address: a.verifier.WalletForChain(chain),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResponse{
		Available: true,
		Domain:    a.cfg.Provisioning.Domain,
		PriceUSD:  a.cfg.Provisioning.PriceUSD,
		QuotaMB:   a.cfg.Provisioning.DefaultQuotaBytes / (1024 * 1024),
		Chains:    wallets,
		IMAP:      fmt.Sprintf("%s:993", a.cfg.Server.Hostname),
		SMTP:      fmt.Sprintf("%s:465", a.cfg.Server.Hostname),
	})
}

type signupRequest struct {
	Username      string `json:"username"`
	AuthPassword  string `json:"auth_password"`
	VaultPassword string `json:"vault_password"`
	TxHash        string `json:"tx_hash"`
	Chain         string `json:"chain"` // "eth", "base", "bsc", "solana"
}

type signupResponse struct {
	OK    bool   `json:"ok"`
	Email string `json:"email"`
	IMAP  string `json:"imap"`
	SMTP  string `json:"smtp"`
	Note  string `json:"note"`
}

func (a *API) handleSignup(w http.ResponseWriter, r *http.Request) {
	// Rate limit: 5 requests per hour per IP.
	// X-Forwarded-For is ignored (no trusted proxy config); trusting it
	// would allow clients to spoof their IP for rate-limit bypass.
	ip := strings.TrimSpace(r.RemoteAddr)
	if !a.limiter.Allow(ip) {
		jsonError(w, "too many requests, try again later", http.StatusTooManyRequests)
		return
	}

	// Limit request body size to 4KB
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	var req signupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate username
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !usernameRegex.MatchString(req.Username) {
		jsonError(w, "username must be 3-32 chars, lowercase alphanumeric with . _ -", http.StatusBadRequest)
		return
	}
	if reservedNames[req.Username] {
		jsonError(w, "username unavailable", http.StatusConflict)
		return
	}

	// Validate passwords
	if err := validatePassword(req.AuthPassword); err != nil {
		jsonError(w, "auth_password: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePassword(req.VaultPassword); err != nil {
		jsonError(w, "vault_password: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate chain
	req.Chain = strings.ToLower(strings.TrimSpace(req.Chain))
	if req.Chain == "" {
		req.Chain = ChainETH // default
	}
	wallet := a.verifier.WalletForChain(req.Chain)
	if wallet == "" {
		jsonError(w, fmt.Sprintf("chain '%s' not supported, use: %s", req.Chain, strings.Join(a.verifier.SupportedChains(), ", ")), http.StatusBadRequest)
		return
	}

	// Validate tx hash format
	if !isValidTxHash(req.TxHash) {
		jsonError(w, "invalid transaction hash format", http.StatusBadRequest)
		return
	}

	domain := a.cfg.Provisioning.Domain

	// Check username availability
	existing, err := a.db.GetUser(req.Username, domain)
	if err != nil {
		a.logger.Error("signup: user lookup error", "error", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if existing != nil {
		jsonError(w, "username unavailable", http.StatusConflict)
		return
	}

	// Check for duplicate payment
	existingPayment, _ := a.db.GetPaymentByTx(req.TxHash)
	if existingPayment != nil {
		jsonError(w, "transaction already used", http.StatusConflict)
		return
	}

	// Verify payment on-chain
	if err := a.verifier.VerifyTransaction(req.TxHash, req.Chain); err != nil {
		a.logger.Warn("payment verification failed", "tx", req.TxHash, "chain", req.Chain, "error", err)
		jsonError(w, "payment verification failed", http.StatusPaymentRequired)
		return
	}

	// Generate vault-enabled crypto keys
	keys, err := a.cryptoSvc.RegisterUserWithVault([]byte(req.AuthPassword), []byte(req.VaultPassword))
	if err != nil {
		a.logger.Error("signup: key generation error", "error", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Create user
	user := &storage.User{
		Username:            req.Username,
		Domain:              domain,
		PasswordHash:        hex.EncodeToString(keys.AuthHash),
		PublicKey:            keys.PublicKey,
		KeyParams:           keys.KeyParams,
		SearchKey:           keys.SearchKey,
		QuotaBytes:          a.cfg.Provisioning.DefaultQuotaBytes,
		VaultHash:           hex.EncodeToString(keys.VaultHash),
		VaultKeyParams:      keys.VaultKeyParams,
		VaultKeyNonce:       keys.VaultKeyNonce,
		VaultWrappedPrivKey: keys.VaultWrappedPrivKey,
	}

	if err := a.db.CreateUser(user); err != nil {
		a.logger.Error("signup: create user error", "error", err)
		jsonError(w, "failed to create account", http.StatusInternalServerError)
		return
	}

	// Record payment as confirmed (we already verified on-chain)
	now := time.Now()
	payment := &storage.Payment{
		TxHash:         req.TxHash,
		WalletAddress:  wallet,
		AmountUSD:      a.cfg.Provisioning.PriceUSD,
		CryptoCurrency: req.Chain,
		Status:         storage.PaymentConfirmed,
		UserID:         &user.ID,
		ConfirmedAt:    &now,
	}
	if err := a.db.CreatePayment(payment); err != nil {
		// CRITICAL: User was created but payment record failed.
		// This means the tx_hash is not recorded and could potentially be reused.
		// Manual intervention required to reconcile.
		a.logger.Error("CRITICAL: signup payment record failed after user creation",
			"error", err, "username", req.Username, "tx", req.TxHash, "chain", req.Chain,
			"user_id", user.ID)
	}

	email := fmt.Sprintf("%s@%s", req.Username, domain)
	a.logger.Info("account provisioned",
		"email", email, "chain", req.Chain, "tx", req.TxHash)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signupResponse{
		OK:    true,
		Email: email,
		IMAP:  fmt.Sprintf("%s:993", a.cfg.Server.Hostname),
		SMTP:  fmt.Sprintf("%s:465", a.cfg.Server.Hostname),
		Note:  "Use auth_password for IMAP/SMTP login. Use vault_password to unlock encrypted messages via POST /api/v1/vault/unlock.",
	})
}

func (a *API) handleVerify(w http.ResponseWriter, r *http.Request) {
	tx := r.PathValue("tx")
	if tx == "" {
		jsonError(w, "tx hash required", http.StatusBadRequest)
		return
	}

	payment, err := a.db.GetPaymentByTx(tx)
	if err != nil || payment == nil {
		jsonError(w, "payment not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tx_hash":    payment.TxHash,
		"status":     paymentStatusStr(payment.Status),
		"chain":      payment.CryptoCurrency,
		"amount_usd": payment.AmountUSD,
		"created_at": payment.CreatedAt.Format(time.RFC3339),
	})
}

func isValidTxHash(hash string) bool {
	if len(hash) < 10 {
		return false
	}
	// Ethereum/Base/BSC: 0x + 64 hex chars
	if strings.HasPrefix(hash, "0x") && len(hash) == 66 {
		_, err := hex.DecodeString(hash[2:])
		return err == nil
	}
	// Bitcoin: 64 hex chars
	if len(hash) == 64 {
		_, err := hex.DecodeString(hash)
		return err == nil
	}
	// Solana: base58, typically 86-88 chars
	if len(hash) >= 43 && len(hash) <= 90 {
		return isValidBase58(hash)
	}
	return false
}

func paymentStatusStr(status int) string {
	switch status {
	case storage.PaymentPending:
		return "pending"
	case storage.PaymentConfirmed:
		return "confirmed"
	case storage.PaymentFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// isValidBase58 checks that a string contains only valid base58 characters.
func isValidBase58(s string) bool {
	const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, c := range s {
		if !strings.ContainsRune(base58Alphabet, c) {
			return false
		}
	}
	return true
}

// validatePassword enforces password strength requirements.
func validatePassword(pw string) error {
	if len(pw) < 12 {
		return fmt.Errorf("must be at least 12 characters")
	}
	if len(pw) > 128 {
		return fmt.Errorf("must be at most 128 characters")
	}
	var hasUpper, hasLower, hasDigit bool
	for _, c := range pw {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("must contain at least one uppercase letter, one lowercase letter, and one digit")
	}
	return nil
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
