// Package tor provides Tor hidden service integration via the Tor control protocol.
//
// This implementation speaks the Tor control protocol (spec: torspec/control-spec.txt)
// directly over TCP, requiring no external Go dependencies. It supports:
//   - Cookie and password authentication to the Tor control port
//   - Creating ephemeral v3 onion services (ADD_ONION)
//   - Removing ephemeral onion services (DEL_ONION)
//   - Reading .onion addresses from existing hidden service directories
package tor

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// Service manages a Tor hidden service for GhostMail.
type Service struct {
	controlAddr    string
	authCookiePath string
	smtpPort       int
	imapPort       int
	httpPort       int
	logger         *slog.Logger

	conn      net.Conn
	reader    *bufio.Reader
	onionAddr string // e.g. "abcdef1234567890.onion"
	keyBlob   string // private key for the ephemeral onion (ED25519-V3:base64)
}

// Config holds Tor service configuration.
type Config struct {
	ControlAddr    string // e.g. "127.0.0.1:9051"
	AuthCookiePath string // path to Tor's control_auth_cookie file
	SMTPPort       int    // local SMTP port to expose via Tor
	IMAPPort       int    // local IMAP port to expose via Tor
	HTTPPort       int    // local admin HTTP port to expose via Tor
}

// NewService creates a new Tor hidden service manager.
func NewService(cfg Config, logger *slog.Logger) *Service {
	return &Service{
		controlAddr:    cfg.ControlAddr,
		authCookiePath: cfg.AuthCookiePath,
		smtpPort:       cfg.SMTPPort,
		imapPort:       cfg.IMAPPort,
		httpPort:       cfg.HTTPPort,
		logger:         logger,
	}
}

// Start connects to the Tor control port, authenticates, and creates
// an ephemeral hidden service mapping ports to the local GhostMail services.
func (s *Service) Start() error {
	s.logger.Info("connecting to Tor control port", "addr", s.controlAddr)

	conn, err := net.DialTimeout("tcp", s.controlAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to Tor control port: %w", err)
	}
	s.conn = conn
	s.reader = bufio.NewReader(conn)

	// Authenticate
	if err := s.authenticate(); err != nil {
		s.conn.Close()
		return fmt.Errorf("Tor authentication: %w", err)
	}
	s.logger.Info("authenticated to Tor control port")

	// Create ephemeral hidden service
	if err := s.createHiddenService(); err != nil {
		s.conn.Close()
		return fmt.Errorf("creating hidden service: %w", err)
	}

	s.logger.Info("Tor hidden service created", "onion", s.onionAddr)
	return nil
}

// Stop removes the ephemeral hidden service and closes the control connection.
func (s *Service) Stop() error {
	if s.conn == nil {
		return nil
	}

	if s.onionAddr != "" {
		// Strip .onion suffix for DEL_ONION
		serviceID := strings.TrimSuffix(s.onionAddr, ".onion")
		resp, err := s.sendCommand(fmt.Sprintf("DEL_ONION %s", serviceID))
		if err != nil {
			s.logger.Warn("failed to remove hidden service", "error", err)
		} else if !strings.HasPrefix(resp, "250") {
			s.logger.Warn("unexpected DEL_ONION response", "response", resp)
		} else {
			s.logger.Info("Tor hidden service removed")
		}
	}

	return s.conn.Close()
}

// OnionAddress returns the .onion address of the hidden service.
func (s *Service) OnionAddress() string {
	return s.onionAddr
}

// --- Control protocol implementation ---

func (s *Service) authenticate() error {
	// Try cookie authentication first
	if s.authCookiePath != "" {
		cookie, err := os.ReadFile(s.authCookiePath)
		if err != nil {
			s.logger.Warn("failed to read auth cookie, trying without auth", "error", err)
		} else {
			cookieHex := hex.EncodeToString(cookie)
			resp, err := s.sendCommand(fmt.Sprintf("AUTHENTICATE %s", cookieHex))
			if err != nil {
				return err
			}
			if strings.HasPrefix(resp, "250") {
				return nil
			}
			s.logger.Warn("cookie auth failed, trying null auth", "response", resp)
		}
	}

	// Try null authentication (for Tor instances with no auth required)
	resp, err := s.sendCommand("AUTHENTICATE")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("authentication failed: %s", resp)
	}
	return nil
}

func (s *Service) createHiddenService() error {
	// Build port mapping: virtual_port,target
	// Maps external ports on the .onion to local ports
	var ports []string
	if s.smtpPort > 0 {
		ports = append(ports, fmt.Sprintf("Port=25,127.0.0.1:%d", s.smtpPort))
	}
	if s.imapPort > 0 {
		ports = append(ports, fmt.Sprintf("Port=993,127.0.0.1:%d", s.imapPort))
	}
	if s.httpPort > 0 {
		ports = append(ports, fmt.Sprintf("Port=443,127.0.0.1:%d", s.httpPort))
	}

	if len(ports) == 0 {
		return fmt.Errorf("no ports configured for hidden service")
	}

	// ADD_ONION creates an ephemeral v3 hidden service
	// NEW:ED25519-V3 tells Tor to generate a new v3 key
	cmd := fmt.Sprintf("ADD_ONION NEW:ED25519-V3 %s", strings.Join(ports, " "))

	resp, err := s.sendCommand(cmd)
	if err != nil {
		return err
	}

	// Parse the multi-line response
	// Expected:
	//   250-ServiceID=<base32 address without .onion>
	//   250-PrivateKey=ED25519-V3:<base64 key>
	//   250 OK
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "ServiceID=") {
			parts := strings.SplitN(line, "ServiceID=", 2)
			if len(parts) == 2 {
				s.onionAddr = strings.TrimSpace(parts[1]) + ".onion"
			}
		}
		if strings.Contains(line, "PrivateKey=") {
			parts := strings.SplitN(line, "PrivateKey=", 2)
			if len(parts) == 2 {
				s.keyBlob = strings.TrimSpace(parts[1])
			}
		}
	}

	if s.onionAddr == "" {
		return fmt.Errorf("failed to parse onion address from response: %s", resp)
	}

	return nil
}

// sendCommand sends a command to the Tor control port and reads the response.
func (s *Service) sendCommand(cmd string) (string, error) {
	_, err := fmt.Fprintf(s.conn, "%s\r\n", cmd)
	if err != nil {
		return "", fmt.Errorf("sending command: %w", err)
	}

	// Read response lines until we get a line starting with "250 " (final) or an error
	var response strings.Builder
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return response.String(), fmt.Errorf("reading response: %w", err)
		}
		response.WriteString(line)

		line = strings.TrimSpace(line)

		// "250 OK" or "250 " is the final success line
		if strings.HasPrefix(line, "250 ") {
			break
		}
		// "250-" is a continuation line, keep reading
		if strings.HasPrefix(line, "250-") {
			continue
		}
		// Error codes (4xx, 5xx)
		if len(line) >= 3 && (line[0] == '4' || line[0] == '5') {
			break
		}
	}

	return response.String(), nil
}

// --- Helper for reading pre-existing hidden service directory ---

// ReadOnionAddress reads a .onion address from a Tor hidden service directory.
// This is used when the operator manages Tor manually via torrc.
func ReadOnionAddress(hiddenServiceDir string) (string, error) {
	data, err := os.ReadFile(hiddenServiceDir + "/hostname")
	if err != nil {
		return "", fmt.Errorf("reading hostname file: %w", err)
	}
	addr := strings.TrimSpace(string(data))
	if !strings.HasSuffix(addr, ".onion") {
		return "", fmt.Errorf("invalid onion address: %s", addr)
	}
	return addr, nil
}
