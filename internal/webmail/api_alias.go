package webmail

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ghostmail/ghostmail/internal/alias"
)

type aliasInfo struct {
	ID           int64   `json:"id"`
	Address      string  `json:"address"`
	Domain       string  `json:"domain"`
	Description  string  `json:"description"`
	IsActive     bool    `json:"is_active"`
	MessageCount int     `json:"message_count"`
	MaxMessages  *int    `json:"max_messages"`
	ExpiresAt    *string `json:"expires_at"`
	CreatedAt    string  `json:"created_at"`
}

func (h *Handler) handleListAliases(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)

	aliases, err := h.db.ListAliases(sess.UserID)
	if err != nil {
		jsonError(w, "failed to list aliases", http.StatusInternalServerError)
		return
	}

	result := make([]aliasInfo, 0, len(aliases))
	for _, a := range aliases {
		info := aliasInfo{
			ID:           a.ID,
			Address:      a.Address,
			Domain:       a.Domain,
			Description:  a.Description,
			IsActive:     a.IsActive,
			MessageCount: a.MessageCount,
			MaxMessages:  a.MaxMessages,
			CreatedAt:    a.CreatedAt.Format("2006-01-02 15:04"),
		}
		if a.ExpiresAt != nil {
			s := a.ExpiresAt.Format(time.RFC3339)
			info.ExpiresAt = &s
		}
		result = append(result, info)
	}

	jsonResponse(w, result)
}

type createAliasRequest struct {
	Description string `json:"description"`
	Domain      string `json:"domain"`
}

func (h *Handler) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)

	var req createAliasRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	domain := req.Domain
	if domain == "" {
		domain = h.cfg.Aliases.DefaultDomain
	}
	if domain == "" {
		domain = sess.Domain
	}

	gen := alias.NewGenerator(h.db, h.cfg.Aliases.MaxPerUser)
	a, err := gen.Create(sess.UserID, domain, req.Description, 0, 0)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonResponse(w, aliasInfo{
		ID:          a.ID,
		Address:     a.Address,
		Domain:      a.Domain,
		Description: a.Description,
		IsActive:    a.IsActive,
		CreatedAt:   a.CreatedAt.Format("2006-01-02 15:04"),
	})
}

func (h *Handler) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id == 0 {
		jsonError(w, "invalid alias id", http.StatusBadRequest)
		return
	}

	// Verify ownership
	aliases, _ := h.db.ListAliases(sess.UserID)
	var owns bool
	for _, a := range aliases {
		if a.ID == id {
			owns = true
			break
		}
	}
	if !owns {
		jsonError(w, "alias not found", http.StatusNotFound)
		return
	}

	if err := h.db.DeleteAlias(id); err != nil {
		jsonError(w, "failed to delete alias", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]bool{"ok": true})
}
