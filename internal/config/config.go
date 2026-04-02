// Package config handles loading and validating the GhostMail configuration.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server  ServerConfig  `toml:"server"`
	TLS     TLSConfig     `toml:"tls"`
	SMTP    SMTPConfig    `toml:"smtp"`
	IMAP    IMAPConfig    `toml:"imap"`
	Crypto  CryptoConfig  `toml:"crypto"`
	Admin   AdminConfig   `toml:"admin"`
	Webmail WebmailConfig `toml:"webmail"`
	Tor     TorConfig     `toml:"tor"`
	Aliases    AliasConfig      `toml:"aliases"`
	Expiry     ExpiryConfig     `toml:"expiry"`
	Privacy    PrivacyConfig    `toml:"privacy"`
	DKIM       DKIMConfig       `toml:"dkim"`
	DNS        DNSConfig        `toml:"dns"`
	Subdomain    SubdomainConfig    `toml:"subdomain"`
	Provisioning ProvisioningConfig `toml:"provisioning"`
}

type ProvisioningConfig struct {
	Enabled           bool    `toml:"enabled"`
	Domain            string  `toml:"domain"`
	CryptoPaymentAddr string  `toml:"crypto_payment_addr"` // Legacy single-address (EVM)
	PriceUSD          float64 `toml:"price_usd"`
	DefaultQuotaBytes int64   `toml:"default_quota_bytes"`
	RateLimitPerHour  int     `toml:"rate_limit_per_hour"`
	Wallets           WalletConfig `toml:"wallets"`
}

type WalletConfig struct {
	EVM    string `toml:"evm"`    // ETH, Base, BSC (0x...)
	Solana string `toml:"solana"` // SOL address
	Tron   string `toml:"tron"`   // Tron address (T...)
}

type WebmailConfig struct {
	Enabled      bool   `toml:"enabled"`
	TorOnly      bool   `toml:"tor_only"`
	OnionAddress string `toml:"onion_address"`
}

type ServerConfig struct {
	Hostname string `toml:"hostname"`
	DataDir  string `toml:"data_dir"`
	PIDFile  string `toml:"pid_file"`
	LogLevel string `toml:"log_level"`
}

type TLSConfig struct {
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	MinVersion string `toml:"min_version"`
}

type SMTPConfig struct {
	ListenAddr     string         `toml:"listen_addr"`
	SubmissionAddr string         `toml:"submission_addr"`
	MaxMessageSize int64          `toml:"max_message_size"`
	MaxRecipients  int            `toml:"max_recipients"`
	RequireTLS     bool           `toml:"require_tls"`
	Greeting       string         `toml:"greeting"`
	Outbound       OutboundConfig `toml:"outbound"`
}

type OutboundConfig struct {
	Enabled              bool   `toml:"enabled"`
	MaxRetries           int    `toml:"max_retries"`
	RetryBaseDelay       string `toml:"retry_base_delay"`
	DeadLetterAfter      string `toml:"dead_letter_after"`
	ConcurrentDeliveries int    `toml:"concurrent_deliveries"`
}

type IMAPConfig struct {
	ListenAddr     string `toml:"listen_addr"`
	IdleTimeout    string `toml:"idle_timeout"`
	MaxConnections int    `toml:"max_connections"`
}

type CryptoConfig struct {
	Argon2Time    uint32 `toml:"argon2_time"`
	Argon2Memory  uint32 `toml:"argon2_memory"`
	Argon2Threads uint8  `toml:"argon2_threads"`
	SessionKeyTTL string `toml:"session_key_ttl"`
	VaultTTL      string `toml:"vault_ttl"`
}

type AdminConfig struct {
	Enabled    bool   `toml:"enabled"`
	ListenAddr string `toml:"listen_addr"`
}

type TorConfig struct {
	Enabled        bool   `toml:"enabled"`
	ControlAddr    string `toml:"control_addr"`
	AuthCookiePath string `toml:"auth_cookie_path"`
}

type AliasConfig struct {
	Enabled       bool   `toml:"enabled"`
	MaxPerUser    int    `toml:"max_per_user"`
	DefaultDomain string `toml:"default_domain"`
}

type ExpiryConfig struct {
	DefaultTTL    string `toml:"default_ttl"`
	TrashTTL      string `toml:"trash_ttl"`
	SpamTTL       string `toml:"spam_ttl"`
	SweepInterval string `toml:"sweep_interval"`
	VacuumInterval string `toml:"vacuum_interval"`
}

type PrivacyConfig struct {
	StripReceivedHeaders  bool `toml:"strip_received_headers"`
	StripUserAgent        bool `toml:"strip_user_agent"`
	StripXOriginatingIP   bool `toml:"strip_x_originating_ip"`
	NormalizeMessageID    bool `toml:"normalize_message_id"`
	LogIPs                bool `toml:"log_ips"`
}

type DKIMConfig struct {
	Selector  string `toml:"selector"`
	KeyBits   int    `toml:"key_bits"`
	ServerKey string `toml:"server_key"` // hex-encoded 256-bit key for encrypting DKIM keys at rest
}

type DNSConfig struct {
	Provider string `toml:"provider"` // "cloudflare", "digitalocean", or empty for manual
	APIKey   string `toml:"api_key"`
	AutoSetup bool  `toml:"auto_setup"` // auto-configure DNS on first boot
}

type SubdomainConfig struct {
	Enabled      bool   `toml:"enabled"`       // enable instant subdomain allocation
	ParentDomain string `toml:"parent_domain"` // e.g., "ghostmail.dev"
	MaxPerIP     int    `toml:"max_per_ip"`    // max subdomains per source IP
}

func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Hostname: "localhost",
			DataDir:  "/var/lib/ghostmail",
			LogLevel: "info",
		},
		TLS: TLSConfig{
			MinVersion: "1.2",
		},
		SMTP: SMTPConfig{
			ListenAddr:     ":25",
			SubmissionAddr: ":587",
			MaxMessageSize: 26214400, // 25MB
			MaxRecipients:  100,
			RequireTLS:     true,
			Greeting:       "GhostMail ESMTP",
			Outbound: OutboundConfig{
				Enabled:              true,
				MaxRetries:           8,
				RetryBaseDelay:       "1m",
				DeadLetterAfter:      "48h",
				ConcurrentDeliveries: 4,
			},
		},
		IMAP: IMAPConfig{
			ListenAddr:     ":993",
			IdleTimeout:    "30m",
			MaxConnections: 100,
		},
		Crypto: CryptoConfig{
			Argon2Time:    3,
			Argon2Memory:  65536, // 64MB
			Argon2Threads: 4,
			SessionKeyTTL: "30m",
			VaultTTL:      "30m",
		},
		Admin: AdminConfig{
			Enabled:    true,
			ListenAddr: ":8443",
		},
		Webmail: WebmailConfig{
			Enabled: true,
		},
		Tor: TorConfig{
			Enabled:     false,
			ControlAddr: "127.0.0.1:9051",
		},
		Aliases: AliasConfig{
			Enabled:    true,
			MaxPerUser: 50,
		},
		Expiry: ExpiryConfig{
			TrashTTL:       "30d",
			SpamTTL:        "7d",
			SweepInterval:  "5m",
			VacuumInterval: "24h",
		},
		Privacy: PrivacyConfig{
			StripReceivedHeaders: true,
			StripUserAgent:       true,
			StripXOriginatingIP:  true,
			NormalizeMessageID:   true,
			LogIPs:               false,
		},
		DKIM: DKIMConfig{
			Selector: "ghostmail",
			KeyBits:  2048,
		},
		DNS: DNSConfig{
			AutoSetup: false,
		},
		Subdomain: SubdomainConfig{
			Enabled:  false,
			MaxPerIP: 3,
		},
		Provisioning: ProvisioningConfig{
			Enabled:           false,
			PriceUSD:          10.0,
			DefaultQuotaBytes: 104857600, // 100MB
			RateLimitPerHour:  10,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply environment variable overrides (GHOSTMAIL_ prefix)
	applyEnvOverrides(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("GHOSTMAIL_HOSTNAME"); v != "" {
		cfg.Server.Hostname = v
	}
	if v := os.Getenv("GHOSTMAIL_DATA_DIR"); v != "" {
		cfg.Server.DataDir = v
	}
	if v := os.Getenv("GHOSTMAIL_LOG_LEVEL"); v != "" {
		cfg.Server.LogLevel = v
	}
	if v := os.Getenv("GHOSTMAIL_TLS_CERT"); v != "" {
		cfg.TLS.CertFile = v
	}
	if v := os.Getenv("GHOSTMAIL_TLS_KEY"); v != "" {
		cfg.TLS.KeyFile = v
	}
	if v := os.Getenv("GHOSTMAIL_SMTP_ADDR"); v != "" {
		cfg.SMTP.ListenAddr = v
	}
	if v := os.Getenv("GHOSTMAIL_IMAP_ADDR"); v != "" {
		cfg.IMAP.ListenAddr = v
	}
	if v := os.Getenv("GHOSTMAIL_ADMIN_ADDR"); v != "" {
		cfg.Admin.ListenAddr = v
	}
	if v := os.Getenv("GHOSTMAIL_DNS_PROVIDER"); v != "" {
		cfg.DNS.Provider = v
	}
	if v := os.Getenv("GHOSTMAIL_DNS_API_KEY"); v != "" {
		cfg.DNS.APIKey = v
	}
	if v := os.Getenv("GHOSTMAIL_SUBDOMAIN_DOMAIN"); v != "" {
		cfg.Subdomain.Enabled = true
		cfg.Subdomain.ParentDomain = v
	}
	if v := os.Getenv("GHOSTMAIL_DKIM_SERVER_KEY"); v != "" {
		cfg.DKIM.ServerKey = v
	}
}

func (c *Config) Validate() error {
	if c.Server.Hostname == "" {
		return fmt.Errorf("server.hostname is required")
	}
	if c.Server.DataDir == "" {
		return fmt.Errorf("server.data_dir is required")
	}

	validLevels := map[string]bool{"error": true, "warn": true, "info": true, "debug": true}
	if !validLevels[strings.ToLower(c.Server.LogLevel)] {
		return fmt.Errorf("invalid log_level %q; must be error, warn, info, or debug", c.Server.LogLevel)
	}

	if c.SMTP.MaxMessageSize <= 0 {
		return fmt.Errorf("smtp.max_message_size must be positive")
	}

	// Validate duration strings
	durationFields := map[string]string{
		"smtp.outbound.retry_base_delay": c.SMTP.Outbound.RetryBaseDelay,
		"smtp.outbound.dead_letter_after": c.SMTP.Outbound.DeadLetterAfter,
		"imap.idle_timeout":               c.IMAP.IdleTimeout,
		"crypto.session_key_ttl":          c.Crypto.SessionKeyTTL,
		"crypto.vault_ttl":                c.Crypto.VaultTTL,
		"expiry.sweep_interval":           c.Expiry.SweepInterval,
		"expiry.vacuum_interval":          c.Expiry.VacuumInterval,
	}
	for name, val := range durationFields {
		if val != "" {
			if _, err := ParseDuration(val); err != nil {
				return fmt.Errorf("invalid duration for %s: %q: %w", name, val, err)
			}
		}
	}

	return nil
}

// ParseDuration extends time.ParseDuration to support "d" (days) suffix.
func ParseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		var days float64
		if _, err := fmt.Sscanf(s, "%f", &days); err != nil {
			return 0, fmt.Errorf("invalid day duration: %s", s)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(s)
}
