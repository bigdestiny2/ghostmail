// Package provisioning provides self-service account creation with crypto payments.
package provisioning

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
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
}

// NewAPI creates a new provisioning API handler.
func NewAPI(cfg *config.Config, db *storage.DB, cryptoSvc *crypto.Service, vaultStore *vault.Store, logger *slog.Logger) *API {
	return &API{
		cfg:        cfg,
		db:         db,
		cryptoSvc:  cryptoSvc,
		vaultStore: vaultStore,
		logger:     logger,
	}
}

// Register attaches provisioning routes to an HTTP mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/provision/status", a.handleStatus)
	mux.HandleFunc("POST /api/v1/provision/signup", a.handleSignup)
	mux.HandleFunc("GET /api/v1/provision/verify/{tx}", a.handleVerify)
}

type statusResponse struct {
	Available      bool    `json:"available"`
	Domain         string  `json:"domain"`
	PriceUSD       float64 `json:"price_usd"`
	QuotaMB        int64   `json:"quota_mb"`
	PaymentAddress string  `json:"payment_address"`
	IMAP           string  `json:"imap"`
	SMTP           string  `json:"smtp"`
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResponse{
		Available:      true,
		Domain:         a.cfg.Provisioning.Domain,
		PriceUSD:       a.cfg.Provisioning.PriceUSD,
		QuotaMB:        a.cfg.Provisioning.DefaultQuotaBytes / (1024 * 1024),
		PaymentAddress: a.cfg.Provisioning.CryptoPaymentAddr,
		IMAP:           fmt.Sprintf("%s:993", a.cfg.Server.Hostname),
		SMTP:           fmt.Sprintf("%s:465", a.cfg.Server.Hostname),
	})
}

type signupRequest struct {
	Username      string `json:"username"`
	AuthPassword  string `json:"auth_password"`
	VaultPassword string `json:"vault_password"`
	TxHash        string `json:"tx_hash"`
}

type signupResponse struct {
	OK    bool   `json:"ok"`
	Email string `json:"email"`
	IMAP  string `json:"imap"`
	SMTP  string `json:"smtp"`
	Note  string `json:"note"`
}

func (a *API) handleSignup(w http.ResponseWriter, r *http.Request) {
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
		jsonError(w, "username is reserved", http.StatusConflict)
		return
	}

	// Validate passwords
	if len(req.AuthPassword) < 8 {
		jsonError(w, "auth_password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if len(req.VaultPassword) < 8 {
		jsonError(w, "vault_password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	// Validate tx hash format (Ethereum: 0x + 64 hex chars)
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
		jsonError(w, "username already taken", http.StatusConflict)
		return
	}

	// Check for duplicate payment
	existingPayment, _ := a.db.GetPaymentByTx(req.TxHash)
	if existingPayment != nil {
		jsonError(w, "transaction already used", http.StatusConflict)
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
		WrappedPrivateKey:   nil, // Not used for vault users
		KeyNonce:            nil, // Not used for vault users
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

	// Record payment
	payment := &storage.Payment{
		TxHash:         req.TxHash,
		WalletAddress:  a.cfg.Provisioning.CryptoPaymentAddr,
		AmountUSD:      a.cfg.Provisioning.PriceUSD,
		CryptoCurrency: "ETH",
		Status:         storage.PaymentPending,
		UserID:         &user.ID,
	}
	if err := a.db.CreatePayment(payment); err != nil {
		a.logger.Error("signup: payment record error", "error", err)
		// Account is created, payment tracking failed — non-fatal
	}

	email := fmt.Sprintf("%s@%s", req.Username, domain)
	a.logger.Info("account provisioned", "email", email, "tx", req.TxHash)

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
		"amount_usd": payment.AmountUSD,
		"created_at": payment.CreatedAt.Format(time.RFC3339),
	})
}

func isValidTxHash(hash string) bool {
	if len(hash) < 10 {
		return false
	}
	// Ethereum: 0x + 64 hex chars
	if strings.HasPrefix(hash, "0x") && len(hash) == 66 {
		_, err := hex.DecodeString(hash[2:])
		return err == nil
	}
	// Bitcoin: 64 hex chars
	if len(hash) == 64 {
		_, err := hex.DecodeString(hash)
		return err == nil
	}
	// Solana: base58, 88 chars typically
	if len(hash) >= 43 && len(hash) <= 88 {
		return true
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

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
