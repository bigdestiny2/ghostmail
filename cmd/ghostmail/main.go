// GhostMail - Ultra-lightweight encrypted email service.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghostmail/ghostmail/internal/admin"
	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/expiry"
	ghostimap "github.com/ghostmail/ghostmail/internal/imap"
	"github.com/ghostmail/ghostmail/internal/logging"
	"github.com/ghostmail/ghostmail/internal/provisioning"
	"github.com/ghostmail/ghostmail/internal/smtp"
	"github.com/ghostmail/ghostmail/internal/storage"
	"github.com/ghostmail/ghostmail/internal/tor"
	"github.com/ghostmail/ghostmail/internal/vault"
	"github.com/ghostmail/ghostmail/internal/webmail"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/ghostmail/ghostmail.toml", "path to configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ghostmail %s\n", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	level := logging.ParseLevel(cfg.Server.LogLevel)
	logger := logging.NewLogger(os.Stdout, level, cfg.Privacy.LogIPs)
	slog.SetDefault(logger)

	logger.Info("ghostmail starting", "version", version, "hostname", cfg.Server.Hostname)

	// Open database
	db, err := storage.Open(cfg.Server.DataDir)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("database opened", "path", db.Path())

	// Create crypto service
	cryptoSvc := crypto.NewService(cfg.Crypto.Argon2Time, cfg.Crypto.Argon2Memory, cfg.Crypto.Argon2Threads)

	// Create vault store
	vaultTTL, _ := config.ParseDuration(cfg.Crypto.VaultTTL)
	if vaultTTL == 0 {
		vaultTTL = 30 * time.Minute
	}
	vaultStore := vault.NewStore(db, cryptoSvc, logger, vaultTTL)

	// Create shutdown context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start vault session sweeper
	go vaultStore.RunSweeper(ctx)

	// Start expiry reaper
	reaper, err := expiry.NewReaper(cfg, db, logger)
	if err != nil {
		logger.Error("failed to create reaper", "error", err)
		os.Exit(1)
	}
	go reaper.Run(ctx)

	// Start outbound sender
	if cfg.SMTP.Outbound.Enabled {
		sender, err := smtp.NewSender(cfg, db, logger)
		if err != nil {
			logger.Error("failed to create sender", "error", err)
			os.Exit(1)
		}
		go sender.Run(ctx)
		logger.Info("outbound sender started")
	}

	// Load TLS configuration if cert files are specified
	var tlsCfg *tls.Config
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			logger.Error("failed to load TLS certificate", "error", err)
			os.Exit(1)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		logger.Info("TLS loaded", "cert", cfg.TLS.CertFile)
	}

	// Start SMTP servers
	smtpServer := smtp.NewServer(cfg, db, logger, tlsCfg, cryptoSvc)
	go func() {
		if err := smtpServer.ListenAndServe(); err != nil {
			logger.Error("SMTP server error", "error", err)
			cancel()
		}
	}()

	// Start IMAP server
	imapServer := ghostimap.NewServer(cfg, db, logger, tlsCfg, cryptoSvc, vaultStore)
	go func() {
		var err error
		if tlsCfg != nil {
			err = imapServer.ListenAndServeTLS(cfg.IMAP.ListenAddr)
		} else {
			err = imapServer.ListenAndServe(cfg.IMAP.ListenAddr)
		}
		if err != nil {
			logger.Error("IMAP server error", "error", err)
			cancel()
		}
	}()

	// Start admin panel
	var adminServer *admin.Server
	var webmailHandler *webmail.Handler
	if cfg.Admin.Enabled {
		var err error
		adminServer, err = admin.NewServer(cfg, db, cryptoSvc, logger, version)
		if err != nil {
			logger.Error("failed to create admin server", "error", err)
			os.Exit(1)
		}

		// Register webmail routes on the admin server's mux
		if cfg.Webmail.Enabled {
			webmailHandler, err = webmail.Register(adminServer.Mux(), db, cryptoSvc, cfg, logger, vaultStore)
			if err != nil {
				logger.Error("failed to register webmail", "error", err)
				os.Exit(1)
			}
		}

		// Register provisioning API
		if cfg.Provisioning.Enabled {
			provAPI := provisioning.NewAPI(cfg, db, cryptoSvc, vaultStore, logger)
			provAPI.Register(adminServer.Mux())
			go provAPI.RunPaymentVerifier(ctx)
			logger.Info("provisioning API enabled", "domain", cfg.Provisioning.Domain)
		}

		go func() {
			if err := adminServer.ListenAndServe(); err != nil {
				logger.Error("admin server error", "error", err)
			}
		}()
	}

	// Start Tor hidden service
	var torService *tor.Service
	if cfg.Tor.Enabled {
		torCfg := tor.Config{
			ControlAddr:    cfg.Tor.ControlAddr,
			AuthCookiePath: cfg.Tor.AuthCookiePath,
			SMTPPort:       parsePort(cfg.SMTP.ListenAddr),
			IMAPPort:       parsePort(cfg.IMAP.ListenAddr),
			HTTPPort:       parsePort(cfg.Admin.ListenAddr),
		}
		torService = tor.NewService(torCfg, logger)
		if err := torService.Start(); err != nil {
			logger.Error("Tor hidden service failed to start", "error", err)
			// Non-fatal: continue without Tor
		} else {
			logger.Info("Tor hidden service active", "onion", torService.OnionAddress())
		}
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("shutting down gracefully", "signal", sig.String())
	case <-ctx.Done():
	}

	// Graceful shutdown: stop accepting new connections, drain existing
	shutdownTimeout := 15 * time.Second
	logger.Info("draining connections", "timeout", shutdownTimeout)

	cancel() // Signal all background goroutines to stop

	// Shut down services in order: stop accepting -> drain -> close
	if torService != nil {
		torService.Stop()
	}
	if webmailHandler != nil {
		webmailHandler.Close()
	}
	if adminServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		adminServer.Close()
		shutdownCancel()
		_ = shutdownCtx
	}
	imapServer.Close()
	smtpServer.Close()

	logger.Info("ghostmail stopped")
}

// parsePort extracts the port number from an address like ":993" or "127.0.0.1:993".
func parsePort(addr string) int {
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		port, err := strconv.Atoi(addr[idx+1:])
		if err == nil {
			return port
		}
	}
	return 0
}
