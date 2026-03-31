// Package admin provides the web admin panel for GhostMail.
package admin

import (
	"crypto/rand"
	"crypto/subtle"
	gotls "crypto/tls"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/ratelimit"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// Server is the admin web panel HTTP server.
type Server struct {
	httpSrv       *http.Server
	mux           *http.ServeMux
	db            *storage.DB
	cfg           *config.Config
	cryptoSvc     *crypto.Service
	logger        *slog.Logger
	pageTemplates map[string]*template.Template
	version       string

	// Session management (in-memory, no external deps)
	mu       sync.RWMutex
	sessions map[string]*adminSession

	// Rate limiters
	authLimiter *ratelimit.Limiter
	reqLimiter  *ratelimit.Limiter
}

type adminSession struct {
	username  string
	createdAt time.Time
}

// NewServer creates the admin web panel server.
func NewServer(cfg *config.Config, db *storage.DB, cryptoSvc *crypto.Service, logger *slog.Logger, version string) (*Server, error) {
	funcMap := template.FuncMap{
		"divf": func(a int64, b int) float64 {
			return float64(a) / float64(b)
		},
		"statusLabel": func(status int) string {
			switch status {
			case 0:
				return "Pending"
			case 1:
				return "Sending"
			case 2:
				return "Sent"
			case 3:
				return "Failed"
			default:
				return "Unknown"
			}
		},
		"deref": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
	}

	// Parse each page template individually with the layout
	pages := []string{"dashboard", "users", "domains", "aliases", "queue", "audit"}
	templates := make(map[string]*template.Template)

	// Login is standalone (no layout)
	loginTmpl, err := template.New("").Funcs(funcMap).ParseFS(staticFiles, "static/templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("parsing login template: %w", err)
	}
	templates["login"] = loginTmpl

	for _, page := range pages {
		t, err := template.New("").Funcs(funcMap).ParseFS(staticFiles,
			"static/templates/layout.html",
			"static/templates/"+page+".html",
		)
		if err != nil {
			return nil, fmt.Errorf("parsing template %s: %w", page, err)
		}
		templates[page] = t
	}

	s := &Server{
		db:            db,
		cfg:           cfg,
		cryptoSvc:     cryptoSvc,
		logger:        logger,
		pageTemplates: templates,
		version:       version,
		sessions:      make(map[string]*adminSession),
		authLimiter:   ratelimit.NewAuthLimiter(),
		reqLimiter:    ratelimit.NewAdminLimiter(),
	}

	mux := http.NewServeMux()

	// Health endpoint (no auth, for Docker health checks and load balancers)
	mux.HandleFunc("GET /health", s.handleHealth)

	// Static files
	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /admin/static/", http.StripPrefix("/admin/static/", http.FileServer(http.FS(staticFS))))

	// Auth routes
	mux.HandleFunc("GET /admin/login", s.handleLoginPage)
	mux.HandleFunc("POST /admin/login", s.handleLogin)
	mux.HandleFunc("GET /admin/logout", s.handleLogout)

	// Protected routes
	mux.HandleFunc("GET /admin/", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("GET /admin/users", s.requireAuth(s.handleUsers))
	mux.HandleFunc("POST /admin/users", s.requireAuth(s.handleCreateUser))
	mux.HandleFunc("POST /admin/users/delete", s.requireAuth(s.handleDeleteUser))
	mux.HandleFunc("GET /admin/domains", s.requireAuth(s.handleDomains))
	mux.HandleFunc("POST /admin/domains", s.requireAuth(s.handleCreateDomain))
	mux.HandleFunc("POST /admin/domains/delete", s.requireAuth(s.handleDeleteDomain))
	mux.HandleFunc("GET /admin/aliases", s.requireAuth(s.handleAliases))
	mux.HandleFunc("POST /admin/aliases/create", s.requireAuth(s.handleCreateAlias))
	mux.HandleFunc("POST /admin/aliases/delete", s.requireAuth(s.handleDeleteAlias))
	mux.HandleFunc("GET /admin/queue", s.requireAuth(s.handleQueue))
	mux.HandleFunc("GET /admin/audit", s.requireAuth(s.handleAudit))

	s.mux = mux
	s.httpSrv = &http.Server{
		Addr:         cfg.Admin.ListenAddr,
		Handler:      s.rateLimitMiddleware(s.securityHeaders(mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// SetTLS configures the admin server to use TLS.
func (s *Server) SetTLS(tlsCfg *gotls.Config) {
	s.httpSrv.TLSConfig = tlsCfg
}

// ListenAndServe starts the admin HTTP(S) server. Uses TLS if configured.
func (s *Server) ListenAndServe() error {
	if s.httpSrv.TLSConfig != nil {
		s.logger.Info("admin panel starting (HTTPS)", "addr", s.httpSrv.Addr)
		return s.httpSrv.ListenAndServeTLS("", "")
	}
	s.logger.Info("admin panel starting (HTTP)", "addr", s.httpSrv.Addr)
	return s.httpSrv.ListenAndServe()
}

// Close shuts down the admin server.
func (s *Server) Close() error {
	return s.httpSrv.Close()
}

// --- Middleware ---

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !s.reqLimiter.Allow(ip) {
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("ghostmail_admin")
		if err != nil {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}

		s.mu.RLock()
		sess, ok := s.sessions[cookie.Value]
		s.mu.RUnlock()

		if !ok || time.Since(sess.createdAt) > 4*time.Hour {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}

		handler(w, r)
	}
}

// --- Session helpers ---

func (s *Server) createSession(username string) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	s.mu.Lock()
	s.sessions[token] = &adminSession{username: username, createdAt: time.Now()}
	s.mu.Unlock()

	return token
}

func (s *Server) deleteSession(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// --- Template rendering ---

type pageData struct {
	Title  string
	Active string
	Flash  string
	Error  string
	Data   interface{}
}

func (s *Server) render(w http.ResponseWriter, page string, data pageData) {
	tmpl, ok := s.pageTemplates[page]
	if !ok {
		s.logger.Error("template not found", "page", page)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("template render error", "page", page, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// --- Auth handlers ---

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.pageTemplates["login"].ExecuteTemplate(w, "login", pageData{})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Rate limit login attempts
	ip := extractIP(r)
	if !s.authLimiter.Allow(ip) {
		s.pageTemplates["login"].ExecuteTemplate(w, "login", pageData{Error: "Too many login attempts. Please wait."})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate: the user must be an admin user in the database
	parts := splitAddr(username)
	if parts == nil {
		// Try as plain username against all domains
		users, _ := s.db.ListUsers()
		for _, u := range users {
			if u.Username == username && u.IsAdmin {
				parts = []string{u.Username, u.Domain}
				break
			}
		}
	}

	if parts == nil {
		s.pageTemplates["login"].ExecuteTemplate(w, "login", pageData{Error: "Invalid credentials"})
		return
	}

	user, err := s.db.GetUser(parts[0], parts[1])
	if err != nil || user == nil || !user.IsAdmin {
		s.pageTemplates["login"].ExecuteTemplate(w, "login", pageData{Error: "Invalid credentials"})
		return
	}

	// Verify password
	authHash, err := hex.DecodeString(user.PasswordHash)
	if err != nil || !crypto.VerifyPassword([]byte(password), mustUnmarshalParams(user.KeyParams), authHash) {
		// Try legacy plain password
		if subtle.ConstantTimeCompare([]byte(user.PasswordHash), []byte(password)) != 1 {
			s.pageTemplates["login"].ExecuteTemplate(w, "login", pageData{Error: "Invalid credentials"})
			return
		}
	}

	token := s.createSession(username)
	http.SetCookie(w, &http.Cookie{
		Name:     "ghostmail_admin",
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   14400, // 4 hours
	})

	s.db.LogAudit(username, "admin.login", "")
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("ghostmail_admin"); err == nil {
		s.deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "ghostmail_admin",
		Value:  "",
		Path:   "/admin",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func splitAddr(addr string) []string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '@' {
			return []string{addr[:i], addr[i+1:]}
		}
	}
	return nil
}

func mustUnmarshalParams(s string) *crypto.KeyParams {
	p, _ := crypto.UnmarshalKeyParams(s)
	if p == nil {
		return &crypto.KeyParams{}
	}
	return p
}

// Mux returns the HTTP mux so other packages (e.g., webmail) can register routes.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// DB returns the database for use by registered route handlers.
func (s *Server) DB() *storage.DB { return s.db }

// CryptoService returns the crypto service.
func (s *Server) CryptoService() *crypto.Service { return s.cryptoSvc }

// Config returns the server configuration.
func (s *Server) Config() *config.Config { return s.cfg }

// Logger returns the server logger.
func (s *Server) Logger() *slog.Logger { return s.logger }

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userCount, _ := s.db.UserCount()
	fmt.Fprintf(w, `{"status":"ok","version":%q,"users":%d}`, s.version, userCount)
}

// extractIP gets the client IP from a request, stripping the port.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For for reverse proxy setups
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take first IP in chain
		if i := len(xff) - 1; i >= 0 {
			for ; i >= 0; i-- {
				if xff[i] == ',' {
					return xff[:i]
				}
			}
		}
		return xff
	}
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
