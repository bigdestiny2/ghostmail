package webmail

import (
	"encoding/json"
	"net/http"
)

type vaultUnlockRequest struct {
	VaultPassword string `json:"vault_password"`
}

func (h *Handler) handleVaultUnlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := h.sessions.GetFromRequest(r)
	if sess == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.vaultStore == nil {
		jsonError(w, "vault not enabled", http.StatusNotImplemented)
		return
	}

	var req vaultUnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.VaultPassword == "" {
		jsonError(w, "vault_password is required", http.StatusBadRequest)
		return
	}

	token, expiresAt, err := h.vaultStore.Unlock(sess.UserID, []byte(req.VaultPassword))
	if err != nil {
		h.logger.Error("vault unlock failed", "user_id", sess.UserID, "error", err)
		jsonError(w, "invalid vault password", http.StatusUnauthorized)
		return
	}

	// Update the web session with the vault keys
	if vs := h.vaultStore.Get(token); vs != nil {
		sess.Keys = vs.Keys
	}

	h.logger.Info("vault unlocked via API", "user_id", sess.UserID)
	jsonResponse(w, map[string]interface{}{
		"ok":         true,
		"token":      token,
		"expires_at": expiresAt.Format("2006-01-02T15:04:05Z"),
	})
}

func (h *Handler) handleVaultLock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := h.sessions.GetFromRequest(r)
	if sess == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.vaultStore == nil {
		jsonError(w, "vault not enabled", http.StatusNotImplemented)
		return
	}

	h.vaultStore.LockUser(sess.UserID)
	sess.Keys = nil

	h.logger.Info("vault locked via API", "user_id", sess.UserID)
	jsonResponse(w, map[string]bool{"ok": true})
}

func (h *Handler) handleVaultStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := h.sessions.GetFromRequest(r)
	if sess == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.vaultStore == nil {
		jsonResponse(w, map[string]interface{}{
			"vault_enabled": false,
		})
		return
	}

	// Check if user is a vault user
	user, err := h.db.GetUserByID(sess.UserID)
	if err != nil || user == nil {
		jsonError(w, "user not found", http.StatusInternalServerError)
		return
	}

	if !user.IsVaultUser() {
		jsonResponse(w, map[string]interface{}{
			"vault_enabled": false,
		})
		return
	}

	vs := h.vaultStore.GetByUser(sess.UserID)
	locked := vs == nil

	resp := map[string]interface{}{
		"vault_enabled": true,
		"locked":        locked,
	}
	if !locked {
		resp["expires_at"] = vs.ExpiresAt.Format("2006-01-02T15:04:05Z")
		// Release cloned keys; we only needed the expiry info.
		vs.Keys.Release()
	}

	jsonResponse(w, resp)
}
