package admin

import (
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
)

func testSetup(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := config.Defaults()
	cfg.Server.DataDir = dir
	cfg.Server.Hostname = "test.ghostmail.local"
	cryptoSvc := crypto.NewService(1, 4096, 1)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Create domain and admin user
	db.CreateDomain(&storage.Domain{Name: "test.com", IsPrimary: true})
	keys, _ := cryptoSvc.RegisterUser([]byte("adminpass"))
	db.CreateUser(&storage.User{
		Username:          "admin",
		Domain:            "test.com",
		PasswordHash:      hex.EncodeToString(keys.AuthHash),
		PublicKey:          keys.PublicKey,
		WrappedPrivateKey: keys.WrappedPrivateKey,
		KeyNonce:          keys.KeyNonce,
		KeyParams:         keys.KeyParams,
		IsAdmin:           true,
		QuotaBytes:        104857600,
	})

	srv, err := NewServer(cfg, db, cryptoSvc, logger, "test")
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestLoginPage(t *testing.T) {
	srv := testSetup(t)

	req := httptest.NewRequest("GET", "/admin/login", nil)
	w := httptest.NewRecorder()
	srv.handleLoginPage(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "GhostMail") {
		t.Error("login page should contain 'GhostMail'")
	}
	if !strings.Contains(w.Body.String(), "Sign In") {
		t.Error("login page should contain 'Sign In' button")
	}
}

func TestLoginSuccess(t *testing.T) {
	srv := testSetup(t)

	form := url.Values{
		"username": {"admin@test.com"},
		"password": {"adminpass"},
	}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/admin/" {
		t.Errorf("expected redirect to /admin/, got %s", w.Header().Get("Location"))
	}

	// Should have a session cookie
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "ghostmail_admin" {
			found = true
			if !c.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
			break
		}
	}
	if !found {
		t.Error("expected ghostmail_admin cookie")
	}
}

func TestLoginFailure(t *testing.T) {
	srv := testSetup(t)

	form := url.Values{
		"username": {"admin@test.com"},
		"password": {"wrongpassword"},
	}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200 (re-show login), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid credentials") {
		t.Error("should show error message")
	}
}

func TestRequireAuth(t *testing.T) {
	srv := testSetup(t)

	// No cookie - should redirect to login
	req := httptest.NewRequest("GET", "/admin/", nil)
	w := httptest.NewRecorder()
	handler := srv.requireAuth(srv.handleDashboard)
	handler(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect, got %d", w.Code)
	}
}

func TestDashboard(t *testing.T) {
	srv := testSetup(t)

	// Create a session
	token := srv.createSession("admin@test.com")

	req := httptest.NewRequest("GET", "/admin/", nil)
	req.AddCookie(&http.Cookie{Name: "ghostmail_admin", Value: token})
	w := httptest.NewRecorder()
	handler := srv.requireAuth(srv.handleDashboard)
	handler(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Error("should render dashboard")
	}
	if !strings.Contains(body, "test.ghostmail.local") {
		t.Error("should show hostname")
	}
}

func TestUsersPage(t *testing.T) {
	srv := testSetup(t)
	token := srv.createSession("admin@test.com")

	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "ghostmail_admin", Value: token})
	w := httptest.NewRecorder()
	handler := srv.requireAuth(srv.handleUsers)
	handler(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "admin@test.com") {
		t.Error("should show existing admin user")
	}
}

func TestDomainsPage(t *testing.T) {
	srv := testSetup(t)
	token := srv.createSession("admin@test.com")

	req := httptest.NewRequest("GET", "/admin/domains", nil)
	req.AddCookie(&http.Cookie{Name: "ghostmail_admin", Value: token})
	w := httptest.NewRecorder()
	handler := srv.requireAuth(srv.handleDomains)
	handler(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "test.com") {
		t.Error("should show existing domain")
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := testSetup(t)

	req := httptest.NewRequest("GET", "/admin/login", nil)
	w := httptest.NewRecorder()
	srv.securityHeaders(http.HandlerFunc(srv.handleLoginPage)).ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("missing CSP")
	}
}

func TestLogout(t *testing.T) {
	srv := testSetup(t)
	token := srv.createSession("admin@test.com")

	req := httptest.NewRequest("GET", "/admin/logout", nil)
	req.AddCookie(&http.Cookie{Name: "ghostmail_admin", Value: token})
	w := httptest.NewRecorder()
	srv.handleLogout(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect, got %d", w.Code)
	}

	// Session should be deleted
	srv.mu.RLock()
	_, exists := srv.sessions[token]
	srv.mu.RUnlock()
	if exists {
		t.Error("session should be deleted after logout")
	}
}
