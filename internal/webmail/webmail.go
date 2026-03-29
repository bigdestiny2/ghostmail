package webmail

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/ratelimit"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// Handler holds all webmail dependencies and serves the webmail UI + API.
type Handler struct {
	db        *storage.DB
	cryptoSvc *crypto.Service
	cfg       *config.Config
	logger    *slog.Logger
	sessions  *SessionStore
	templates map[string]*template.Template
	authLimit *ratelimit.Limiter
	stop      chan struct{}
}

// Register attaches webmail routes to an existing HTTP mux.
func Register(mux *http.ServeMux, db *storage.DB, cryptoSvc *crypto.Service, cfg *config.Config, logger *slog.Logger) (*Handler, error) {
	h := &Handler{
		db:        db,
		cryptoSvc: cryptoSvc,
		cfg:       cfg,
		logger:    logger,
		sessions:  NewSessionStore(logger),
		templates: make(map[string]*template.Template),
		authLimit: ratelimit.NewAuthLimiter(),
		stop:      make(chan struct{}),
	}

	// Parse templates
	loginTmpl, err := template.New("").ParseFS(staticFiles, "static/templates/webmail_login.html")
	if err != nil {
		return nil, err
	}
	h.templates["login"] = loginTmpl

	appTmpl, err := template.New("").ParseFS(staticFiles, "static/templates/webmail_app.html")
	if err != nil {
		return nil, err
	}
	h.templates["app"] = appTmpl

	// Start session sweeper
	h.sessions.StartSweeper(h.stop)

	// Static assets
	webmailFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /mail/static/", http.StripPrefix("/mail/static/", http.FileServer(http.FS(webmailFS))))

	// Page routes
	mux.HandleFunc("GET /mail/login", h.handleLoginPage)
	mux.HandleFunc("GET /mail/", h.requireAuth(h.handleApp))
	mux.HandleFunc("GET /mail", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/mail/", http.StatusMovedPermanently)
	})

	// Auth API
	mux.HandleFunc("POST /api/v1/auth/login", h.handleAPILogin)
	mux.HandleFunc("POST /api/v1/auth/logout", h.handleAPILogout)

	// Mailbox API
	mux.HandleFunc("GET /api/v1/mailboxes", h.requireAuthAPI(h.handleListMailboxes))
	mux.HandleFunc("GET /api/v1/mailboxes/{name}/messages", h.requireAuthAPI(h.handleListMessages))

	// Message API
	mux.HandleFunc("GET /api/v1/messages/{mailboxID}/{uid}", h.requireAuthAPI(h.handleGetMessage))
	mux.HandleFunc("POST /api/v1/messages/send", h.requireAuthAPI(h.handleSendMessage))
	mux.HandleFunc("POST /api/v1/messages/{mailboxID}/{uid}/flags", h.requireAuthAPI(h.handleUpdateFlags))
	mux.HandleFunc("POST /api/v1/messages/{mailboxID}/{uid}/move", h.requireAuthAPI(h.handleMoveMessage))
	mux.HandleFunc("DELETE /api/v1/messages/{mailboxID}/{uid}", h.requireAuthAPI(h.handleDeleteMessage))

	// Search API
	mux.HandleFunc("POST /api/v1/search", h.requireAuthAPI(h.handleSearch))

	// Alias API
	mux.HandleFunc("GET /api/v1/aliases", h.requireAuthAPI(h.handleListAliases))
	mux.HandleFunc("POST /api/v1/aliases", h.requireAuthAPI(h.handleCreateAlias))
	mux.HandleFunc("DELETE /api/v1/aliases/{id}", h.requireAuthAPI(h.handleDeleteAlias))

	logger.Info("webmail routes registered")
	return h, nil
}

// Close stops the session sweeper and releases all sessions.
func (h *Handler) Close() {
	close(h.stop)
	h.sessions.ReleaseAll()
}

// --- Middleware ---

func (h *Handler) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := h.sessions.GetFromRequest(r)
		if sess == nil {
			http.Redirect(w, r, "/mail/login", http.StatusSeeOther)
			return
		}
		handler(w, r)
	}
}

func (h *Handler) requireAuthAPI(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := h.sessions.GetFromRequest(r)
		if sess == nil {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

// --- Page handlers ---

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to inbox
	if sess := h.sessions.GetFromRequest(r); sess != nil {
		http.Redirect(w, r, "/mail/", http.StatusSeeOther)
		return
	}
	h.templates["login"].ExecuteTemplate(w, "webmail_login", nil)
}

func (h *Handler) handleApp(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)
	data := map[string]string{
		"Username": sess.Username,
		"Domain":   sess.Domain,
		"Email":    sess.Username + "@" + sess.Domain,
	}
	h.templates["app"].ExecuteTemplate(w, "webmail_app", data)
}

// --- JSON helpers ---

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
