// Package imap implements the IMAP server for GhostMail.
package imap

import (
	"crypto/tls"
	"log/slog"
	"net"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
	"github.com/ghostmail/ghostmail/internal/vault"
)

// Server wraps the go-imap v2 server.
type Server struct {
	srv       *imapserver.Server
	cfg       *config.Config
	db        *storage.DB
	logger    *slog.Logger
	cryptoSvc *crypto.Service
	vaultStore *vault.Store

	// Track active mailbox trackers for cross-session notifications
	mu       sync.Mutex
	trackers map[int64]*imapserver.MailboxTracker // key: mailbox ID
}

// NewServer creates a new IMAP server.
func NewServer(cfg *config.Config, db *storage.DB, logger *slog.Logger, tlsCfg *tls.Config, cryptoSvc *crypto.Service, vaultStore *vault.Store) *Server {
	s := &Server{
		cfg:        cfg,
		db:         db,
		logger:     logger,
		cryptoSvc:  cryptoSvc,
		vaultStore: vaultStore,
		trackers:   make(map[int64]*imapserver.MailboxTracker),
	}

	caps := imap.CapSet{
		imap.CapIMAP4rev1: {},
		imap.CapIMAP4rev2: {},
		imap.CapIdle:      {},
	}

	opts := &imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return s.newSession(conn), nil, nil
		},
		Caps:         caps,
		TLSConfig:    tlsCfg,
		InsecureAuth: false, // never allow auth without TLS
		Logger:       &slogAdapter{logger},
	}

	s.srv = imapserver.New(opts)
	return s
}

func (s *Server) newSession(conn *imapserver.Conn) *Session {
	return &Session{
		server:     s,
		db:         s.db,
		cfg:        s.cfg,
		logger:     s.logger,
		vaultStore: s.vaultStore,
	}
}

// GetTracker returns or creates a MailboxTracker for the given mailbox.
func (s *Server) GetTracker(mailboxID int64, numMessages uint32) *imapserver.MailboxTracker {
	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.trackers[mailboxID]; ok {
		return t
	}
	t := imapserver.NewMailboxTracker(numMessages)
	s.trackers[mailboxID] = t
	return t
}

// NotifyNewMessage notifies all sessions watching a mailbox that a new message arrived.
func (s *Server) NotifyNewMessage(mailboxID int64, numMessages uint32) {
	s.mu.Lock()
	t, ok := s.trackers[mailboxID]
	s.mu.Unlock()

	if ok {
		t.QueueNumMessages(numMessages)
	}
}

// ListenAndServeTLS starts the IMAPS server.
func (s *Server) ListenAndServeTLS(addr string) error {
	s.logger.Info("IMAP server starting", "addr", addr)
	return s.srv.ListenAndServeTLS(addr)
}

// ListenAndServe starts the IMAP server without TLS (for dev/testing).
func (s *Server) ListenAndServe(addr string) error {
	s.logger.Info("IMAP server starting (no TLS)", "addr", addr)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.srv.Serve(ln)
}

// Close shuts down the IMAP server.
func (s *Server) Close() error {
	return s.srv.Close()
}

// slogAdapter adapts slog.Logger to imapserver.Logger.
type slogAdapter struct {
	logger *slog.Logger
}

func (a *slogAdapter) Printf(format string, args ...interface{}) {
	a.logger.Debug("imap: "+format, args...)
}
