package tor

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadOnionAddress(t *testing.T) {
	dir := t.TempDir()
	addr := "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion"
	if err := os.WriteFile(filepath.Join(dir, "hostname"), []byte(addr+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadOnionAddress(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != addr {
		t.Errorf("got %q, want %q", got, addr)
	}
}

func TestReadOnionAddressMissing(t *testing.T) {
	_, err := ReadOnionAddress("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing directory")
	}
}

func TestReadOnionAddressInvalid(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hostname"), []byte("not-an-onion-address\n"), 0600)

	_, err := ReadOnionAddress(dir)
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestNewService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg := Config{
		ControlAddr: "127.0.0.1:9051",
		SMTPPort:    25,
		IMAPPort:    993,
		HTTPPort:    8443,
	}
	svc := NewService(cfg, logger)
	if svc.controlAddr != "127.0.0.1:9051" {
		t.Errorf("controlAddr = %q", svc.controlAddr)
	}
	if svc.OnionAddress() != "" {
		t.Error("should have no address before Start")
	}
}

// TestControlProtocol uses a mock Tor control server to test the protocol.
func TestControlProtocol(t *testing.T) {
	// Start a mock Tor control server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Mock server goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read AUTHENTICATE
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AUTHENTICATE") {
			fmt.Fprintf(conn, "250 OK\r\n")
		}

		// Read ADD_ONION
		line, _ = reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ADD_ONION") {
			fmt.Fprintf(conn, "250-ServiceID=testabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr\r\n")
			fmt.Fprintf(conn, "250-PrivateKey=ED25519-V3:dGVzdGtleQ==\r\n")
			fmt.Fprintf(conn, "250 OK\r\n")
		}

		// Read DEL_ONION
		line, _ = reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DEL_ONION") {
			fmt.Fprintf(conn, "250 OK\r\n")
		}
	}()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := NewService(Config{
		ControlAddr: addr,
		SMTPPort:    2525,
		IMAPPort:    1993,
		HTTPPort:    8443,
	}, logger)

	if err := svc.Start(); err != nil {
		t.Fatal("Start:", err)
	}

	onion := svc.OnionAddress()
	if onion == "" {
		t.Fatal("expected onion address")
	}
	if !strings.HasSuffix(onion, ".onion") {
		t.Errorf("onion address should end with .onion: %s", onion)
	}

	if svc.keyBlob == "" {
		t.Error("expected private key blob")
	}

	if err := svc.Stop(); err != nil {
		t.Fatal("Stop:", err)
	}

	<-done
}

func TestControlProtocolAuthFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		reader.ReadString('\n')
		fmt.Fprintf(conn, "515 Authentication failed\r\n")
	}()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := NewService(Config{
		ControlAddr: ln.Addr().String(),
		SMTPPort:    25,
	}, logger)

	err = svc.Start()
	if err == nil {
		t.Error("expected auth failure error")
		svc.Stop()
	}
}
