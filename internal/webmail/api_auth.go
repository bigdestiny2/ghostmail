package webmail

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ghostmail/ghostmail/internal/crypto"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)
	if !h.authLimit.Allow(ip) {
		jsonError(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(req.Email, "@", 2)
	if len(parts) != 2 {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	username, domain := parts[0], parts[1]

	user, err := h.db.GetUser(username, domain)
	if err != nil || user == nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password and derive session keys
	authHash, err := hex.DecodeString(user.PasswordHash)
	if err != nil || len(authHash) == 0 {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	params, err := crypto.UnmarshalKeyParams(user.KeyParams)
	if err != nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	var sessionKeys *crypto.SessionKeys
	vaultLocked := false

	if user.IsVaultUser() {
		// Vault user: auth password only proves identity
		if err := h.cryptoSvc.AuthenticateAuthOnly([]byte(req.Password), user.KeyParams, authHash); err != nil {
			jsonError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		// Check if vault is already unlocked
		if h.vaultStore != nil {
			if vs := h.vaultStore.GetByUser(user.ID); vs != nil {
				sessionKeys = vs.Keys
			}
		}
		if sessionKeys == nil {
			vaultLocked = true
		}
	} else {
		// Legacy user: auth + decrypt in one step
		sessionKeys, err = h.cryptoSvc.Authenticate(
			[]byte(req.Password),
			user.KeyParams,
			authHash,
			user.WrappedPrivateKey,
			user.KeyNonce,
		)
		if err != nil {
			// Fallback: verify with just password hash for legacy accounts
			if !crypto.VerifyPassword([]byte(req.Password), params, authHash) {
				jsonError(w, "invalid credentials", http.StatusUnauthorized)
				return
			}
			sessionKeys = nil
		}
	}

	sess := &WebSession{
		UserID:    user.ID,
		Username:  user.Username,
		Domain:    user.Domain,
		IsAdmin:   user.IsAdmin,
		Keys:      sessionKeys,
		CreatedAt: time.Now(),
	}

	token := h.sessions.Create(sess)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	h.logger.Info("webmail login", "user", req.Email, "vault_locked", vaultLocked)
	jsonResponse(w, map[string]interface{}{
		"ok":           true,
		"username":     user.Username,
		"domain":       user.Domain,
		"email":        user.Username + "@" + user.Domain,
		"vault_locked": vaultLocked,
	})
}

// handleFormLogin handles traditional form POST login with redirect (more reliable cookie handling).
func (h *Handler) handleFormLogin(w http.ResponseWriter, r *http.Request) {
	// CSRF check: verify Origin header matches our host for form-based login
	if origin := r.Header.Get("Origin"); origin != "" {
		if !strings.HasSuffix(origin, "://"+r.Host) && !strings.HasSuffix(origin, "://"+h.cfg.Server.Hostname) {
			h.templates["login"].ExecuteTemplate(w, "webmail_login", map[string]string{"Error": "Invalid request origin"})
			return
		}
	}

	ip := extractIP(r)
	if !h.authLimit.Allow(ip) {
		h.templates["login"].ExecuteTemplate(w, "webmail_login", map[string]string{"Error": "Too many login attempts"})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		h.templates["login"].ExecuteTemplate(w, "webmail_login", map[string]string{"Error": "Invalid credentials"})
		return
	}
	username, domain := parts[0], parts[1]

	user, err := h.db.GetUser(username, domain)
	if err != nil || user == nil {
		h.templates["login"].ExecuteTemplate(w, "webmail_login", map[string]string{"Error": "Invalid credentials"})
		return
	}

	authHash, err := hex.DecodeString(user.PasswordHash)
	if err != nil || len(authHash) == 0 {
		h.templates["login"].ExecuteTemplate(w, "webmail_login", map[string]string{"Error": "Invalid credentials"})
		return
	}

	var sessionKeys *crypto.SessionKeys
	vaultLocked := false

	if user.IsVaultUser() {
		if err := h.cryptoSvc.AuthenticateAuthOnly([]byte(password), user.KeyParams, authHash); err != nil {
			h.templates["login"].ExecuteTemplate(w, "webmail_login", map[string]string{"Error": "Invalid credentials"})
			return
		}
		if h.vaultStore != nil {
			if vs := h.vaultStore.GetByUser(user.ID); vs != nil {
				sessionKeys = vs.Keys
			}
		}
		if sessionKeys == nil {
			vaultLocked = true
		}
	} else {
		sessionKeys, err = h.cryptoSvc.Authenticate(
			[]byte(password),
			user.KeyParams,
			authHash,
			user.WrappedPrivateKey,
			user.KeyNonce,
		)
		if err != nil {
			params, _ := crypto.UnmarshalKeyParams(user.KeyParams)
			if params == nil || !crypto.VerifyPassword([]byte(password), params, authHash) {
				h.templates["login"].ExecuteTemplate(w, "webmail_login", map[string]string{"Error": "Invalid credentials"})
				return
			}
			sessionKeys = nil
		}
	}

	sess := &WebSession{
		UserID:    user.ID,
		Username:  user.Username,
		Domain:    user.Domain,
		IsAdmin:   user.IsAdmin,
		Keys:      sessionKeys,
		CreatedAt: time.Now(),
	}
	token := h.sessions.Create(sess)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	_ = vaultLocked
	h.logger.Info("webmail login", "user", email, "vault_locked", vaultLocked)
	http.Redirect(w, r, "/mail/", http.StatusSeeOther)
}

func (h *Handler) handleAPILogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		h.sessions.Delete(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	jsonResponse(w, map[string]bool{"ok": true})
}

// extractIP gets the client IP from a request, stripping the port.
// X-Forwarded-For is ignored because there is no trusted proxy configuration;
// trusting it would allow clients to spoof their IP for rate-limit bypass.
func extractIP(r *http.Request) string {
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}
