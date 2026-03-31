package admin

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ghostmail/ghostmail/internal/alias"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// --- Dashboard ---

type dashboardData struct {
	UserCount   int
	DomainCount int
	AliasCount  int
	QueueSize   int
	Hostname    string
	Version     string
	DataDir     string
	SMTPAddr    string
	IMAPAddr    string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	userCount, _ := s.db.UserCount()
	domains, _ := s.db.ListDomains()
	queueSize, _ := s.db.QueueSize()

	// Count all aliases across all users
	aliasCount := 0
	users, _ := s.db.ListUsers()
	for _, u := range users {
		aliases, _ := s.db.ListAliases(u.ID)
		aliasCount += len(aliases)
	}

	s.render(w, "dashboard", pageData{
		Title:     "Dashboard",
		Active:    "dashboard",
		CSRFToken: s.getCSRFToken(r),
		Data: dashboardData{
			UserCount:   userCount,
			DomainCount: len(domains),
			AliasCount:  aliasCount,
			QueueSize:   queueSize,
			Hostname:    s.cfg.Server.Hostname,
			Version:     s.version,
			DataDir:     s.cfg.Server.DataDir,
			SMTPAddr:    s.cfg.SMTP.ListenAddr,
			IMAPAddr:    s.cfg.IMAP.ListenAddr,
		},
	})
}

// --- Users ---

type usersData struct {
	Users   []*storage.User
	Domains []*storage.Domain
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, _ := s.db.ListUsers()
	domains, _ := s.db.ListDomains()

	s.render(w, "users", pageData{
		Title:     "Users",
		Active:    "users",
		Flash:     r.URL.Query().Get("flash"),
		Error:     r.URL.Query().Get("error"),
		CSRFToken: s.getCSRFToken(r),
		Data:      usersData{Users: users, Domains: domains},
	})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	domain := r.FormValue("domain")
	password := r.FormValue("password")

	if username == "" || domain == "" || password == "" {
		http.Redirect(w, r, "/admin/users?error=All+fields+required", http.StatusSeeOther)
		return
	}

	// Generate crypto keys
	keys, err := s.cryptoSvc.RegisterUser([]byte(password))
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	u := &storage.User{
		Username:          username,
		Domain:            domain,
		PasswordHash:      hex.EncodeToString(keys.AuthHash),
		PublicKey:          keys.PublicKey,
		WrappedPrivateKey: keys.WrappedPrivateKey,
		KeyNonce:          keys.KeyNonce,
		KeyParams:         keys.KeyParams,
		SearchKey:         keys.SearchKey,
		QuotaBytes:        104857600,
	}
	if err := s.db.CreateUser(u); err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	s.db.LogAudit("admin", "user.create", username+"@"+domain)
	http.Redirect(w, r, "/admin/users?flash="+url.QueryEscape("User "+username+"@"+domain+" created"), http.StatusSeeOther)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.FormValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/users?error=Invalid+user+ID", http.StatusSeeOther)
		return
	}

	user, _ := s.db.GetUserByID(id)
	if user == nil {
		http.Redirect(w, r, "/admin/users?error=User+not+found", http.StatusSeeOther)
		return
	}

	if err := s.db.DeleteUser(id); err != nil {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	s.db.LogAudit("admin", "user.delete", user.Username+"@"+user.Domain)
	http.Redirect(w, r, "/admin/users?flash=User+deleted", http.StatusSeeOther)
}

// --- Domains ---

type domainsData struct {
	Domains []*storage.Domain
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	domains, _ := s.db.ListDomains()
	s.render(w, "domains", pageData{
		Title:     "Domains",
		Active:    "domains",
		Flash:     r.URL.Query().Get("flash"),
		Error:     r.URL.Query().Get("error"),
		CSRFToken: s.getCSRFToken(r),
		Data:      domainsData{Domains: domains},
	})
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	primary := r.FormValue("primary") == "1"

	if name == "" {
		http.Redirect(w, r, "/admin/domains?error=Domain+name+required", http.StatusSeeOther)
		return
	}

	d := &storage.Domain{Name: name, IsPrimary: primary}
	if err := s.db.CreateDomain(d); err != nil {
		http.Redirect(w, r, "/admin/domains?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	s.db.LogAudit("admin", "domain.add", name)
	http.Redirect(w, r, "/admin/domains?flash="+url.QueryEscape("Domain "+name+" added"), http.StatusSeeOther)
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	idStr := r.FormValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/domains?error=Invalid+domain+ID", http.StatusSeeOther)
		return
	}

	if err := s.db.DeleteDomain(id); err != nil {
		http.Redirect(w, r, "/admin/domains?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	s.db.LogAudit("admin", "domain.delete", idStr)
	http.Redirect(w, r, "/admin/domains?flash=Domain+removed", http.StatusSeeOther)
}

// --- Aliases ---

type aliasesData struct {
	Aliases []aliasWithOwner
	Users   []*storage.User
	Domains []*storage.Domain
}

type aliasWithOwner struct {
	Alias     *storage.Alias
	OwnerName string
}

func (s *Server) handleAliases(w http.ResponseWriter, r *http.Request) {
	users, _ := s.db.ListUsers()
	domains, _ := s.db.ListDomains()
	var allAliases []aliasWithOwner

	for _, u := range users {
		aliases, _ := s.db.ListAliases(u.ID)
		for _, a := range aliases {
			allAliases = append(allAliases, aliasWithOwner{
				Alias:     a,
				OwnerName: u.Username + "@" + u.Domain,
			})
		}
	}

	s.render(w, "aliases", pageData{
		Title:     "Aliases",
		Active:    "aliases",
		Flash:     r.URL.Query().Get("flash"),
		Error:     r.URL.Query().Get("error"),
		CSRFToken: s.getCSRFToken(r),
		Data:      aliasesData{Aliases: allAliases, Users: users, Domains: domains},
	})
}

func (s *Server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.FormValue("user_id")
	domain := r.FormValue("domain")
	description := r.FormValue("description")

	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil || domain == "" {
		http.Redirect(w, r, "/admin/aliases?error=Invalid+input", http.StatusSeeOther)
		return
	}

	aliasGen := alias.NewGenerator(s.db, s.cfg.Aliases.MaxPerUser)
	a, err := aliasGen.Create(userID, domain, description, 0, 0)
	if err != nil {
		http.Redirect(w, r, "/admin/aliases?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	s.db.LogAudit("admin", "alias.create", a.Address)
	http.Redirect(w, r, "/admin/aliases?flash="+url.QueryEscape("Alias "+a.Address+" created"), http.StatusSeeOther)
}

func (s *Server) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	idStr := r.FormValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/aliases?error=Invalid+alias+ID", http.StatusSeeOther)
		return
	}

	if err := s.db.DeleteAlias(id); err != nil {
		http.Redirect(w, r, "/admin/aliases?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	s.db.LogAudit("admin", "alias.delete", idStr)
	http.Redirect(w, r, "/admin/aliases?flash=Alias+deleted", http.StatusSeeOther)
}

// --- Queue ---

type queueData struct {
	Items []*storage.QueueItem
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	items, _ := s.db.DequeueMessages(100) // Just reading, not actually dequeuing
	s.render(w, "queue", pageData{
		Title:     "Send Queue",
		Active:    "queue",
		CSRFToken: s.getCSRFToken(r),
		Data:      queueData{Items: items},
	})
}

// --- Audit ---

type auditData struct {
	Entries []*storage.AuditEntry
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, _ := s.db.ListAuditLog(100)
	s.render(w, "audit", pageData{
		Title:     "Audit Log",
		Active:    "audit",
		CSRFToken: s.getCSRFToken(r),
		Data:      auditData{Entries: entries},
	})
}
