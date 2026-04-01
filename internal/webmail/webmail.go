package webmail

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/ratelimit"
	"github.com/ghostmail/ghostmail/internal/storage"
	"github.com/ghostmail/ghostmail/internal/vault"
)

// Handler holds all webmail dependencies and serves the webmail UI + API.
type Handler struct {
	db         *storage.DB
	cryptoSvc  *crypto.Service
	cfg        *config.Config
	logger     *slog.Logger
	sessions   *SessionStore
	templates  map[string]*template.Template
	authLimit   *ratelimit.Limiter
	searchLimit *ratelimit.Limiter
	vaultStore  *vault.Store
	otv        *OTVStore
	stop       chan struct{}
}

// Register attaches webmail routes to an existing HTTP mux.
func Register(mux *http.ServeMux, db *storage.DB, cryptoSvc *crypto.Service, cfg *config.Config, logger *slog.Logger, vaultStore *vault.Store) (*Handler, error) {
	h := &Handler{
		db:         db,
		cryptoSvc:  cryptoSvc,
		cfg:        cfg,
		logger:     logger,
		sessions:   NewSessionStore(logger),
		templates:  make(map[string]*template.Template),
		authLimit:   ratelimit.NewAuthLimiter(),
		searchLimit: ratelimit.NewAuthLimiter(),
		vaultStore: vaultStore,
		otv:        NewOTVStore(),
		stop:       make(chan struct{}),
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

	// OTV templates (inline, not from embed FS)
	h.templates["otv_view"] = otvViewTemplate
	h.templates["otv_error"] = otvErrorTemplate

	// Start session sweeper and OTV sweeper
	h.sessions.StartSweeper(h.stop)
	h.otv.StartSweeper(h.stop)

	// Static assets
	webmailFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /mail/static/", http.StripPrefix("/mail/static/", http.FileServer(http.FS(webmailFS))))

	// Page routes
	mux.HandleFunc("GET /mail/login", h.handleLoginPage)
	mux.HandleFunc("GET /mail/", h.requireAuth(h.handleApp))
	mux.HandleFunc("POST /mail/", h.requireAuth(h.handleApp)) // POST fallback for login redirect
	mux.HandleFunc("GET /mail", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/mail/", http.StatusMovedPermanently)
	})

	// Auth API
	mux.HandleFunc("POST /api/v1/auth/login", h.handleAPILogin)
	mux.HandleFunc("POST /api/v1/auth/logout", h.handleAPILogout)

	// Form-based login (browser redirect flow)
	mux.HandleFunc("POST /mail/login", h.handleFormLogin)

	// Mailbox API
	mux.HandleFunc("GET /api/v1/mailboxes", h.requireAuthAPI(h.handleListMailboxes))
	mux.HandleFunc("GET /api/v1/mailboxes/{name}/messages", h.requireAuthAPI(h.handleListMessages))

	// Message API
	mux.HandleFunc("GET /api/v1/messages/{mailboxID}/{uid}", h.requireAuthAPI(h.handleGetMessage))
	mux.HandleFunc("POST /api/v1/messages/send", h.requireAuthAPI(h.handleSendMessage))
	mux.HandleFunc("POST /api/v1/messages/{mailboxID}/{uid}/flags", h.requireAuthAPI(h.handleUpdateFlags))
	mux.HandleFunc("POST /api/v1/messages/{mailboxID}/{uid}/move", h.requireAuthAPI(h.handleMoveMessage))
	mux.HandleFunc("DELETE /api/v1/messages/{mailboxID}/{uid}", h.requireAuthAPI(h.handleDeleteMessage))

	// Vault API
	mux.HandleFunc("POST /api/v1/vault/unlock", h.requireAuthAPI(h.handleVaultUnlock))
	mux.HandleFunc("POST /api/v1/vault/lock", h.requireAuthAPI(h.handleVaultLock))
	mux.HandleFunc("GET /api/v1/vault/status", h.requireAuthAPI(h.handleVaultStatus))

	// Search API
	mux.HandleFunc("POST /api/v1/search", h.requireAuthAPI(h.handleSearch))

	// OTV (One-Time View) API
	mux.HandleFunc("POST /api/v1/otv/create", h.requireAuthAPI(h.handleCreateOTV))
	mux.HandleFunc("GET /mail/view/{token}", h.handleViewOTV)

	// Compose link (opens webmail with pre-filled compose modal)
	mux.HandleFunc("GET /mail/compose", h.requireAuth(h.handleComposeLink))

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
			h.logger.Warn("webmail API auth failed", "path", r.URL.Path, "has_cookie", r.Header.Get("Cookie") != "")
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// CSRF protection: require custom header on state-changing requests.
		// Browsers will not send custom headers cross-origin without CORS preflight.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-GhostMail-CSRF") == "" {
				jsonError(w, "missing CSRF header", http.StatusForbidden)
				return
			}
		}

		handler(w, r)
	}
}

// --- Page handlers ---

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	// If already logged in, redirect to inbox
	if sess := h.sessions.GetFromRequest(r); sess != nil {
		http.Redirect(w, r, "/mail/", http.StatusSeeOther)
		return
	}
	h.templates["login"].ExecuteTemplate(w, "webmail_login", nil)
}

func (h *Handler) handleApp(w http.ResponseWriter, r *http.Request) {
	// Security headers for webmail pages
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-src blob:; img-src 'self' data:")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	sess := h.sessions.GetFromRequest(r)
	data := map[string]string{
		"Username": sess.Username,
		"Domain":   sess.Domain,
		"Email":    sess.Username + "@" + sess.Domain,
	}
	h.templates["app"].ExecuteTemplate(w, "webmail_app", data)
}

// handleComposeLink serves the webmail app with URL params that auto-open the compose modal.
// GET /mail/compose?to=X&subject=Y&cc=Z&body=B
func (h *Handler) handleComposeLink(w http.ResponseWriter, r *http.Request) {
	// Security headers
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-src blob:; img-src 'self' data:")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	sess := h.sessions.GetFromRequest(r)
	// Sanitize compose params — strip CRLF to prevent header injection in meta tags.
	// Go's html/template auto-escapes HTML, but we sanitize as defense in depth.
	sanitize := func(s string) string {
		return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(s)
	}
	data := map[string]string{
		"Username":       sess.Username,
		"Domain":         sess.Domain,
		"Email":          sess.Username + "@" + sess.Domain,
		"ComposeTo":      sanitize(r.URL.Query().Get("to")),
		"ComposeSubject": sanitize(r.URL.Query().Get("subject")),
		"ComposeCC":      sanitize(r.URL.Query().Get("cc")),
		"ComposeBody":    sanitize(r.URL.Query().Get("body")),
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
