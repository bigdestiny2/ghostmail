package webmail

import (
	"html/template"
	"net"
	"net/http"
	"strings"
)

// torGate wraps a handler to block clearnet requests when tor_only mode is enabled.
// Requests with a .onion Host header pass through; all others get a landing page.
func (h *Handler) torGate(handler http.HandlerFunc) http.HandlerFunc {
	if !h.cfg.Webmail.TorOnly {
		return handler
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if isTorRequest(r) {
			handler(w, r)
			return
		}
		h.logger.Info("webmail tor-gate blocked clearnet request", "host", r.Host, "path", r.URL.Path)
		h.serveTorLandingPage(w, r)
	}
}

// torGateAPI wraps an API handler to return JSON 403 for clearnet requests.
func (h *Handler) torGateAPI(handler http.HandlerFunc) http.HandlerFunc {
	if !h.cfg.Webmail.TorOnly {
		return handler
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if isTorRequest(r) {
			handler(w, r)
			return
		}
		jsonError(w, "webmail is only accessible via Tor", http.StatusForbidden)
	}
}

// isTorRequest checks if the request arrived through a Tor hidden service.
func isTorRequest(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.HasSuffix(host, ".onion")
}

func (h *Handler) serveTorLandingPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	// Add Onion-Location header so Tor Browser auto-redirects
	if h.cfg.Webmail.OnionAddress != "" {
		w.Header().Set("Onion-Location", "http://"+h.cfg.Webmail.OnionAddress+r.URL.Path)
	}

	w.WriteHeader(http.StatusForbidden)
	torLandingTemplate.Execute(w, map[string]string{
		"OnionAddress": h.cfg.Webmail.OnionAddress,
	})
}

var torLandingTemplate = template.Must(template.New("tor_landing").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostMail - Tor Required</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117; color: #c9d1d9;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; padding: 2rem;
        }
        .container { max-width: 500px; text-align: center; }
        .icon { font-size: 3rem; margin-bottom: 1rem; }
        h1 { font-size: 1.5rem; color: #00b4d8; margin-bottom: 0.5rem; }
        h2 { font-size: 1.1rem; color: #f0f6fc; margin-bottom: 1rem; }
        p { font-size: 0.95rem; color: #8b949e; line-height: 1.6; margin-bottom: 1rem; }
        .onion-box {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; padding: 1rem; margin: 1.5rem 0;
            word-break: break-all;
        }
        .onion-box a {
            color: #58a6ff; text-decoration: none; font-family: monospace; font-size: 0.85rem;
        }
        .onion-box a:hover { text-decoration: underline; }
        .label { font-size: 0.75rem; color: #8b949e; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .tor-link {
            display: inline-block; margin-top: 1rem;
            color: #58a6ff; text-decoration: none; font-size: 0.9rem;
        }
        .tor-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">&#x1F6E1;</div>
        <h1>GhostMail</h1>
        <h2>Tor Access Required</h2>
        <p>This webmail service is only accessible through the Tor network to protect your privacy.</p>
        {{if .OnionAddress}}
        <div class="onion-box">
            <div class="label">Onion Address</div>
            <a href="http://{{.OnionAddress}}/mail/login">{{.OnionAddress}}</a>
        </div>
        {{end}}
        <p>Open this address in Tor Browser to access your encrypted inbox.</p>
        <a class="tor-link" href="https://www.torproject.org/download/" rel="noopener noreferrer">Download Tor Browser &rarr;</a>
    </div>
</body>
</html>`))
