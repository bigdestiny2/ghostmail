// Package smtp implements the inbound and outbound SMTP server for GhostMail.
package smtp

import (
	"crypto/tls"
	"log/slog"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// Server wraps the go-smtp server for inbound mail reception.
type Server struct {
	inbound    *smtp.Server
	submission *smtp.Server
	db         *storage.DB
	cfg        *config.Config
	logger     *slog.Logger
}

// NewServer creates inbound (port 25) and submission (port 587) SMTP servers.
func NewServer(cfg *config.Config, db *storage.DB, logger *slog.Logger, tlsCfg *tls.Config, cryptoSvc ...*crypto.Service) *Server {
	s := &Server{
		db:     db,
		cfg:    cfg,
		logger: logger,
	}

	var csvc *crypto.Service
	if len(cryptoSvc) > 0 {
		csvc = cryptoSvc[0]
	}

	// Inbound server (port 25) - receives mail from external MTAs
	backend := &Backend{
		db:        db,
		cfg:       cfg,
		logger:    logger,
		cryptoSvc: csvc,
		requireAuth: false,
	}
	s.inbound = smtp.NewServer(backend)
	s.inbound.Addr = cfg.SMTP.ListenAddr
	s.inbound.Domain = cfg.Server.Hostname
	s.inbound.ReadTimeout = 60 * time.Second
	s.inbound.WriteTimeout = 60 * time.Second
	s.inbound.MaxMessageBytes = cfg.SMTP.MaxMessageSize
	s.inbound.MaxRecipients = cfg.SMTP.MaxRecipients
	s.inbound.AllowInsecureAuth = false
	if tlsCfg != nil {
		s.inbound.TLSConfig = tlsCfg
	}

	// Submission server (port 587) - authenticated sending from clients
	submissionBackend := &Backend{
		db:        db,
		cfg:       cfg,
		logger:    logger,
		cryptoSvc: csvc,
		requireAuth: true,
	}
	s.submission = smtp.NewServer(submissionBackend)
	s.submission.Addr = cfg.SMTP.SubmissionAddr
	s.submission.Domain = cfg.Server.Hostname
	s.submission.ReadTimeout = 60 * time.Second
	s.submission.WriteTimeout = 120 * time.Second
	s.submission.MaxMessageBytes = cfg.SMTP.MaxMessageSize
	s.submission.MaxRecipients = cfg.SMTP.MaxRecipients
	s.submission.AllowInsecureAuth = false
	if tlsCfg != nil {
		s.submission.TLSConfig = tlsCfg
	}

	return s
}

// ListenAndServe starts both SMTP servers.
func (s *Server) ListenAndServe() error {
	errCh := make(chan error, 2)

	go func() {
		s.logger.Info("SMTP inbound server starting", "addr", s.inbound.Addr)
		errCh <- s.inbound.ListenAndServe()
	}()

	go func() {
		s.logger.Info("SMTP submission server starting", "addr", s.submission.Addr)
		errCh <- s.submission.ListenAndServe()
	}()

	return <-errCh
}

// Close gracefully shuts down both servers.
func (s *Server) Close() error {
	err1 := s.inbound.Close()
	err2 := s.submission.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
