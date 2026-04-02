package webmail

import (
	"log/slog"
	"os"

	"github.com/ghostmail/ghostmail/internal/config"
)

func testConfig(torOnly bool) *config.Config {
	cfg := config.Defaults()
	cfg.Webmail.TorOnly = torOnly
	cfg.Webmail.OnionAddress = "testaddr1234567890.onion"
	return cfg
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}
