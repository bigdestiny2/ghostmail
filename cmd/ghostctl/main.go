// ghostctl - CLI admin tool for GhostMail.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ghostmail/ghostmail/internal/crypto"
	gdkim "github.com/ghostmail/ghostmail/internal/dkim"
	"github.com/ghostmail/ghostmail/internal/dns"
	"github.com/ghostmail/ghostmail/internal/storage"
	"github.com/ghostmail/ghostmail/internal/subdomain"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	dataDir := os.Getenv("GHOSTMAIL_DATA_DIR")
	if dataDir == "" {
		dataDir = "/var/lib/ghostmail"
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version":
		fmt.Printf("ghostctl %s\n", version)
	case "user":
		handleUser(dataDir, args)
	case "domain":
		handleDomain(dataDir, args)
	case "dkim":
		handleDKIM(dataDir, args)
	case "alias":
		handleAlias(dataDir, args)
	case "pgp":
		handlePGP(dataDir, args)
	case "dns":
		handleDNS(dataDir, args)
	case "subdomain":
		handleSubdomain(dataDir, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: ghostctl <command> [args]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  version          Print version")
	fmt.Fprintln(os.Stderr, "  user create      Create a new user")
	fmt.Fprintln(os.Stderr, "  user list        List all users")
	fmt.Fprintln(os.Stderr, "  user delete      Delete a user")
	fmt.Fprintln(os.Stderr, "  domain add       Add a domain")
	fmt.Fprintln(os.Stderr, "  domain list      List domains")
	fmt.Fprintln(os.Stderr, "  domain remove    Remove a domain")
	fmt.Fprintln(os.Stderr, "  dkim generate    Generate DKIM keys for a domain")
	fmt.Fprintln(os.Stderr, "  dkim dns         Show DNS records for a domain")
	fmt.Fprintln(os.Stderr, "  pgp import       Import a PGP public key for a contact")
	fmt.Fprintln(os.Stderr, "  pgp list         List PGP keys for a user")
	fmt.Fprintln(os.Stderr, "  pgp delete       Delete a PGP key")
	fmt.Fprintln(os.Stderr, "  alias create     Create a disposable alias")
	fmt.Fprintln(os.Stderr, "  alias list       List aliases for a user")
	fmt.Fprintln(os.Stderr, "  alias delete     Delete an alias")
	fmt.Fprintln(os.Stderr, "  dns setup        Auto-configure DNS records via provider API")
	fmt.Fprintln(os.Stderr, "  dns verify       Verify DNS record propagation")
	fmt.Fprintln(os.Stderr, "  dns detect       Detect DNS provider for a domain")
	fmt.Fprintln(os.Stderr, "  subdomain create Allocate a subdomain on shared domain")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Environment:")
	fmt.Fprintln(os.Stderr, "  GHOSTMAIL_DATA_DIR  Data directory (default: /var/lib/ghostmail)")
}

func openDB(dataDir string) *storage.DB {
	db, err := storage.Open(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	return db
}

func handleUser(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: ghostctl user <create|list|delete>")
		os.Exit(1)
	}

	db := openDB(dataDir)
	defer db.Close()

	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("user create", flag.ExitOnError)
		username := fs.String("username", "", "username (local part)")
		domain := fs.String("domain", "", "domain")
		password := fs.String("password", "", "password")
		admin := fs.Bool("admin", false, "make admin")
		fs.Parse(args[1:])

		if *username == "" || *domain == "" || *password == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl user create -username alice -domain example.com -password secret")
			os.Exit(1)
		}

		// Generate cryptographic keys for the user
		cryptoSvc := crypto.NewService(3, 65536, 4) // Argon2id: t=3, m=64MB, p=4
		keys, err := cryptoSvc.RegisterUser([]byte(*password))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating keys: %v\n", err)
			os.Exit(1)
		}

		u := &storage.User{
			Username:          *username,
			Domain:            *domain,
			PasswordHash:      hex.EncodeToString(keys.AuthHash),
			PublicKey:          keys.PublicKey,
			WrappedPrivateKey: keys.WrappedPrivateKey,
			KeyNonce:          keys.KeyNonce,
			KeyParams:         keys.KeyParams,
			SearchKey:         keys.SearchKey,
			IsAdmin:           *admin,
			QuotaBytes:        104857600, // 100MB default
		}
		if err := db.CreateUser(u); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("User created: %s@%s (ID: %d) [encrypted]\n", u.Username, u.Domain, u.ID)
		db.LogAudit("cli", "user.create", *username+"@"+*domain)

	case "list":
		users, err := db.ListUsers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(users) == 0 {
			fmt.Println("No users found.")
			return
		}
		fmt.Printf("%-4s %-20s %-6s %-20s\n", "ID", "Address", "Admin", "Created")
		fmt.Println(strings.Repeat("-", 54))
		for _, u := range users {
			admin := ""
			if u.IsAdmin {
				admin = "yes"
			}
			fmt.Printf("%-4d %-20s %-6s %-20s\n",
				u.ID,
				u.Username+"@"+u.Domain,
				admin,
				u.CreatedAt.Format(time.RFC3339),
			)
		}

	case "delete":
		fs := flag.NewFlagSet("user delete", flag.ExitOnError)
		username := fs.String("username", "", "username")
		domain := fs.String("domain", "", "domain")
		fs.Parse(args[1:])

		if *username == "" || *domain == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl user delete -username alice -domain example.com")
			os.Exit(1)
		}

		user, err := db.GetUser(*username, *domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if user == nil {
			fmt.Fprintln(os.Stderr, "user not found")
			os.Exit(1)
		}
		if err := db.DeleteUser(user.ID); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("User deleted: %s@%s\n", *username, *domain)
		db.LogAudit("cli", "user.delete", *username+"@"+*domain)

	default:
		fmt.Fprintf(os.Stderr, "unknown user command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleDomain(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: ghostctl domain <add|list|remove>")
		os.Exit(1)
	}

	db := openDB(dataDir)
	defer db.Close()

	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("domain add", flag.ExitOnError)
		name := fs.String("name", "", "domain name")
		primary := fs.Bool("primary", false, "set as primary domain")
		fs.Parse(args[1:])

		if *name == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl domain add -name example.com [-primary]")
			os.Exit(1)
		}

		d := &storage.Domain{Name: *name, IsPrimary: *primary}
		if err := db.CreateDomain(d); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Domain added: %s (ID: %d)\n", d.Name, d.ID)
		db.LogAudit("cli", "domain.add", *name)

	case "list":
		domains, err := db.ListDomains()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(domains) == 0 {
			fmt.Println("No domains found.")
			return
		}
		fmt.Printf("%-4s %-30s %-8s %-20s\n", "ID", "Domain", "Primary", "Created")
		fmt.Println(strings.Repeat("-", 66))
		for _, d := range domains {
			primary := ""
			if d.IsPrimary {
				primary = "yes"
			}
			fmt.Printf("%-4d %-30s %-8s %-20s\n",
				d.ID, d.Name, primary, d.CreatedAt.Format(time.RFC3339))
		}

	case "remove":
		fs := flag.NewFlagSet("domain remove", flag.ExitOnError)
		name := fs.String("name", "", "domain name")
		fs.Parse(args[1:])

		if *name == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl domain remove -name example.com")
			os.Exit(1)
		}

		d, err := db.GetDomain(*name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if d == nil {
			fmt.Fprintln(os.Stderr, "domain not found")
			os.Exit(1)
		}
		if err := db.DeleteDomain(d.ID); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Domain removed: %s\n", *name)
		db.LogAudit("cli", "domain.remove", *name)

	default:
		fmt.Fprintf(os.Stderr, "unknown domain command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleAlias(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: ghostctl alias <create|list|delete>")
		os.Exit(1)
	}

	db := openDB(dataDir)
	defer db.Close()

	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("alias create", flag.ExitOnError)
		username := fs.String("user", "", "username")
		domain := fs.String("domain", "", "domain for alias")
		desc := fs.String("description", "", "description")
		fs.Parse(args[1:])

		if *username == "" || *domain == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl alias create -user alice -domain example.com [-description 'signup']")
			os.Exit(1)
		}

		parts := strings.SplitN(*username, "@", 2)
		var user *storage.User
		var err error
		if len(parts) == 2 {
			user, err = db.GetUser(parts[0], parts[1])
		} else {
			user, err = db.GetUser(*username, *domain)
		}
		if err != nil || user == nil {
			fmt.Fprintln(os.Stderr, "user not found")
			os.Exit(1)
		}

		// Generate random alias address
		alias := &storage.Alias{
			UserID:      user.ID,
			Address:     generateAliasAddr(*domain),
			Domain:      *domain,
			Description: *desc,
			IsActive:    true,
		}
		if err := db.CreateAlias(alias); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Alias created: %s -> %s@%s\n", alias.Address, user.Username, user.Domain)
		db.LogAudit("cli", "alias.create", alias.Address)

	case "list":
		fs := flag.NewFlagSet("alias list", flag.ExitOnError)
		username := fs.String("user", "", "username")
		domain := fs.String("domain", "", "domain")
		fs.Parse(args[1:])

		if *username == "" || *domain == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl alias list -user alice -domain example.com")
			os.Exit(1)
		}

		user, err := db.GetUser(*username, *domain)
		if err != nil || user == nil {
			fmt.Fprintln(os.Stderr, "user not found")
			os.Exit(1)
		}

		aliases, err := db.ListAliases(user.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(aliases) == 0 {
			fmt.Println("No aliases found.")
			return
		}
		fmt.Printf("%-4s %-30s %-8s %-6s %-20s\n", "ID", "Address", "Active", "Msgs", "Description")
		fmt.Println(strings.Repeat("-", 72))
		for _, a := range aliases {
			active := "yes"
			if !a.IsActive {
				active = "no"
			}
			fmt.Printf("%-4d %-30s %-8s %-6d %-20s\n",
				a.ID, a.Address, active, a.MessageCount, a.Description)
		}

	case "delete":
		fs := flag.NewFlagSet("alias delete", flag.ExitOnError)
		address := fs.String("address", "", "alias address")
		fs.Parse(args[1:])

		if *address == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl alias delete -address random123@example.com")
			os.Exit(1)
		}

		alias, err := db.ResolveAlias(*address)
		if err != nil || alias == nil {
			fmt.Fprintln(os.Stderr, "alias not found")
			os.Exit(1)
		}
		if err := db.DeleteAlias(alias.ID); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Alias deleted: %s\n", *address)
		db.LogAudit("cli", "alias.delete", *address)

	default:
		fmt.Fprintf(os.Stderr, "unknown alias command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleDKIM(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: ghostctl dkim <generate|dns>")
		os.Exit(1)
	}

	db := openDB(dataDir)
	defer db.Close()

	switch args[0] {
	case "generate":
		fs := flag.NewFlagSet("dkim generate", flag.ExitOnError)
		domainName := fs.String("domain", "", "domain name")
		selector := fs.String("selector", "ghostmail", "DKIM selector")
		keyType := fs.String("type", "rsa", "key type: rsa or ed25519")
		bits := fs.Int("bits", 2048, "RSA key size (ignored for ed25519)")
		fs.Parse(args[1:])

		if *domainName == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl dkim generate -domain example.com [-selector ghostmail] [-type rsa] [-bits 2048]")
			os.Exit(1)
		}

		d, err := db.GetDomain(*domainName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if d == nil {
			fmt.Fprintf(os.Stderr, "domain %q not found. Add it first: ghostctl domain add -name %s\n", *domainName, *domainName)
			os.Exit(1)
		}

		var privKeyData []byte
		var dnsRecord string

		switch *keyType {
		case "rsa":
			privKeyData, dnsRecord, err = gdkim.GenerateRSAKey(*bits)
		case "ed25519":
			var privKey []byte
			privKey, dnsRecord, err = gdkim.GenerateEd25519Key()
			if err == nil {
				privKeyData = privKey
			}
		default:
			fmt.Fprintf(os.Stderr, "unsupported key type: %s (use rsa or ed25519)\n", *keyType)
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating key: %v\n", err)
			os.Exit(1)
		}

		// Update domain record with DKIM keys
		_, err = db.Exec(`UPDATE domains SET dkim_selector = ?, dkim_private_key = ?, dkim_public_key = ? WHERE id = ?`,
			*selector, privKeyData, dnsRecord, d.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error saving DKIM key: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("DKIM key generated for %s (selector: %s, type: %s)\n\n", *domainName, *selector, *keyType)
		fmt.Println("Add the following DNS records:")
		fmt.Println(gdkim.FormatDNSRecord(*selector, *domainName, dnsRecord))
		fmt.Println()
		fmt.Println(gdkim.FormatSPFRecord(*domainName))
		fmt.Println()
		fmt.Println(gdkim.FormatDMARCRecord(*domainName, ""))
		fmt.Println()

		db.LogAudit("cli", "dkim.generate", *domainName)

	case "dns":
		fs := flag.NewFlagSet("dkim dns", flag.ExitOnError)
		domainName := fs.String("domain", "", "domain name")
		fs.Parse(args[1:])

		if *domainName == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl dkim dns -domain example.com")
			os.Exit(1)
		}

		d, err := db.GetDomain(*domainName)
		if err != nil || d == nil {
			fmt.Fprintln(os.Stderr, "domain not found")
			os.Exit(1)
		}

		if d.DKIMPublicKey == "" {
			fmt.Fprintln(os.Stderr, "No DKIM key configured. Run: ghostctl dkim generate -domain", *domainName)
			os.Exit(1)
		}

		fmt.Printf("DNS records for %s:\n\n", *domainName)
		fmt.Println(gdkim.FormatDNSRecord(d.DKIMSelector, *domainName, d.DKIMPublicKey))
		fmt.Println()
		fmt.Println(gdkim.FormatSPFRecord(*domainName))
		fmt.Println()
		fmt.Println(gdkim.FormatDMARCRecord(*domainName, ""))

	default:
		fmt.Fprintf(os.Stderr, "unknown dkim command: %s\n", args[0])
		os.Exit(1)
	}
}

func handlePGP(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: ghostctl pgp <import|list|delete>")
		os.Exit(1)
	}

	db := openDB(dataDir)
	defer db.Close()

	pgpSvc := crypto.NewPGPService()

	switch args[0] {
	case "import":
		fs := flag.NewFlagSet("pgp import", flag.ExitOnError)
		username := fs.String("user", "", "username (user@domain)")
		email := fs.String("email", "", "contact email address")
		keyFile := fs.String("keyfile", "", "path to armored PGP public key file")
		fs.Parse(args[1:])

		if *username == "" || *email == "" || *keyFile == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl pgp import -user alice@example.com -email bob@external.com -keyfile bob.asc")
			os.Exit(1)
		}

		parts := strings.SplitN(*username, "@", 2)
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "username must be in user@domain format")
			os.Exit(1)
		}
		user, err := db.GetUser(parts[0], parts[1])
		if err != nil || user == nil {
			fmt.Fprintln(os.Stderr, "user not found")
			os.Exit(1)
		}

		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading key file: %v\n", err)
			os.Exit(1)
		}

		keyInfo, err := pgpSvc.ImportPublicKey(string(keyData))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error importing key: %v\n", err)
			os.Exit(1)
		}

		if err := db.StorePGPKey(user.ID, *email, keyInfo.PublicKeyBytes, keyInfo.Fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "error storing key: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("PGP key imported for %s\n", *email)
		fmt.Printf("  Fingerprint: %s\n", keyInfo.Fingerprint)
		fmt.Printf("  Key ID:      %s\n", keyInfo.KeyID)
		fmt.Printf("  Stored in:   %s's keyring\n", *username)
		db.LogAudit("cli", "pgp.import", *email)

	case "list":
		fs := flag.NewFlagSet("pgp list", flag.ExitOnError)
		username := fs.String("user", "", "username (user@domain)")
		fs.Parse(args[1:])

		if *username == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl pgp list -user alice@example.com")
			os.Exit(1)
		}

		parts := strings.SplitN(*username, "@", 2)
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "username must be in user@domain format")
			os.Exit(1)
		}
		user, err := db.GetUser(parts[0], parts[1])
		if err != nil || user == nil {
			fmt.Fprintln(os.Stderr, "user not found")
			os.Exit(1)
		}

		keys, err := db.ListPGPKeys(user.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(keys) == 0 {
			fmt.Println("No PGP keys in keyring.")
			return
		}
		fmt.Printf("%-4s %-30s %-44s %-20s\n", "ID", "Contact", "Fingerprint", "Added")
		fmt.Println(strings.Repeat("-", 102))
		for _, k := range keys {
			fmt.Printf("%-4d %-30s %-44s %-20s\n",
				k.ID, k.Email, k.Fingerprint, k.CreatedAt.Format(time.RFC3339))
		}

	case "delete":
		fs := flag.NewFlagSet("pgp delete", flag.ExitOnError)
		id := fs.Int64("id", 0, "PGP key ID")
		fs.Parse(args[1:])

		if *id == 0 {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl pgp delete -id 1")
			os.Exit(1)
		}

		if err := db.DeletePGPKey(*id); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("PGP key deleted.")
		db.LogAudit("cli", "pgp.delete", fmt.Sprintf("%d", *id))

	default:
		fmt.Fprintf(os.Stderr, "unknown pgp command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleDNS(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: ghostctl dns <setup|verify|detect>")
		os.Exit(1)
	}

	switch args[0] {
	case "detect":
		fs := flag.NewFlagSet("dns detect", flag.ExitOnError)
		domain := fs.String("domain", "", "domain to check")
		fs.Parse(args[1:])

		if *domain == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl dns detect -domain example.com")
			os.Exit(1)
		}

		provider, err := dns.DetectProvider(*domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not detect provider: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("DNS provider for %s: %s\n", *domain, provider)

	case "setup":
		fs := flag.NewFlagSet("dns setup", flag.ExitOnError)
		domain := fs.String("domain", "", "email domain")
		provider := fs.String("provider", "", "DNS provider (cloudflare, digitalocean)")
		apiKey := fs.String("api-key", "", "provider API key/token")
		serverIP := fs.String("ip", "", "server IP (auto-detected if empty)")
		fs.Parse(args[1:])

		if *domain == "" || *provider == "" || *apiKey == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl dns setup -domain example.com -provider cloudflare -api-key <token> [-ip 1.2.3.4]")
			os.Exit(1)
		}

		// Auto-detect server IP if not provided
		if *serverIP == "" {
			resp, err := http.Get("https://ifconfig.me")
			if err != nil {
				fmt.Fprintln(os.Stderr, "Could not detect server IP. Use -ip flag.")
				os.Exit(1)
			}
			defer resp.Body.Close()
			body := make([]byte, 64)
			n, _ := resp.Body.Read(body)
			*serverIP = strings.TrimSpace(string(body[:n]))
			fmt.Printf("Detected server IP: %s\n", *serverIP)
		}

		// Get DKIM record if available
		db := openDB(dataDir)
		d, _ := db.GetDomain(*domain)
		var dkimRec string
		if d != nil && d.DKIMPublicKey != "" {
			dkimRec = d.DKIMPublicKey
		}
		db.Close()

		p, err := dns.NewProvider(*provider, *apiKey, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Configuring DNS records for %s via %s...\n\n", *domain, p.Name())

		ctx := context.Background()
		results, err := dns.SetupAll(ctx, p, *domain, "mail."+*domain, *serverIP, dkimRec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		for _, r := range results {
			icon := "+"
			switch r.Status {
			case "exists":
				icon = "="
			case "error":
				icon = "!"
			}
			fmt.Printf("  [%s] %-6s %-40s %s\n", icon, r.Record.Type, r.Record.Name, r.Record.Value)
			if r.Error != nil {
				fmt.Printf("        error: %v\n", r.Error)
			}
		}

		fmt.Println()
		fmt.Println("Legend: [+] created  [=] already exists  [!] error")
		fmt.Println()
		fmt.Println("DNS records may take 5-60 minutes to propagate.")
		fmt.Println("Verify with: ghostctl dns verify -domain", *domain)

	case "verify":
		fs := flag.NewFlagSet("dns verify", flag.ExitOnError)
		domain := fs.String("domain", "", "domain to verify")
		serverIP := fs.String("ip", "", "expected server IP")
		fs.Parse(args[1:])

		if *domain == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl dns verify -domain example.com [-ip 1.2.3.4]")
			os.Exit(1)
		}

		fmt.Printf("Verifying DNS records for %s...\n\n", *domain)

		results, err := dns.VerifyAll(*domain, "mail."+*domain, *serverIP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		allOK := true
		for _, r := range results {
			icon := "PASS"
			if !r.OK {
				icon = "FAIL"
				allOK = false
			}
			fmt.Printf("  [%s] %-6s %-40s\n", icon, r.Type, r.Name)
			fmt.Printf("         %s\n", r.Details)
		}

		fmt.Println()
		if allOK {
			fmt.Println("All DNS records verified! Your email server is ready to receive mail.")
		} else {
			fmt.Println("Some records are missing. Add them at your domain registrar and wait for propagation.")
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown dns command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleSubdomain(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: ghostctl subdomain <create>")
		os.Exit(1)
	}

	db := openDB(dataDir)
	defer db.Close()

	logger := slog.Default()

	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("subdomain create", flag.ExitOnError)
		parentDomain := fs.String("parent", "", "parent domain (e.g., ghostmail.dev)")
		name := fs.String("name", "", "custom subdomain name (optional, random if empty)")
		adminUser := fs.String("admin-user", "admin", "admin username")
		adminPass := fs.String("admin-pass", "", "admin password (auto-generated if empty)")
		fs.Parse(args[1:])

		if *parentDomain == "" {
			// Check env
			*parentDomain = os.Getenv("GHOSTMAIL_SUBDOMAIN_DOMAIN")
		}
		if *parentDomain == "" {
			fmt.Fprintln(os.Stderr, "Usage: ghostctl subdomain create -parent ghostmail.dev [-name mymail] [-admin-user admin] [-admin-pass secret]")
			fmt.Fprintln(os.Stderr, "  Or set GHOSTMAIL_SUBDOMAIN_DOMAIN environment variable")
			os.Exit(1)
		}

		// Auto-generate password if not set
		if *adminPass == "" {
			b := make([]byte, 18)
			f, _ := os.Open("/dev/urandom")
			f.Read(b)
			f.Close()
			*adminPass = hex.EncodeToString(b)[:24]
		}

		svc := subdomain.NewService(db, *parentDomain, logger)

		var alloc *subdomain.Allocation
		var err error
		if *name != "" {
			alloc, err = svc.GenerateCustomSubdomain(*name, *adminUser, *adminPass)
		} else {
			alloc, err = svc.Allocate(*adminUser, *adminPass)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		// Create admin user on the new subdomain
		cryptoSvc := crypto.NewService(3, 65536, 4)
		keys, err := cryptoSvc.RegisterUser([]byte(*adminPass))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating keys: %v\n", err)
			os.Exit(1)
		}

		u := &storage.User{
			Username:          *adminUser,
			Domain:            alloc.FQDN,
			PasswordHash:      hex.EncodeToString(keys.AuthHash),
			PublicKey:          keys.PublicKey,
			WrappedPrivateKey: keys.WrappedPrivateKey,
			KeyNonce:          keys.KeyNonce,
			KeyParams:         keys.KeyParams,
			SearchKey:         keys.SearchKey,
			IsAdmin:           true,
			QuotaBytes:        104857600,
		}
		if err := db.CreateUser(u); err != nil {
			fmt.Fprintf(os.Stderr, "error creating user: %v\n", err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println("========================================")
		fmt.Println("  Subdomain Allocated!")
		fmt.Println("========================================")
		fmt.Println()
		fmt.Printf("  Domain:    %s\n", alloc.FQDN)
		fmt.Printf("  Email:     %s\n", alloc.OwnerEmail)
		fmt.Printf("  Password:  %s\n", *adminPass)
		fmt.Println()
		fmt.Printf("  Webmail:   https://mail.%s/mail/\n", *parentDomain)
		fmt.Printf("  IMAP:      mail.%s:993\n", *parentDomain)
		fmt.Printf("  SMTP:      mail.%s:587\n", *parentDomain)
		fmt.Println()
		fmt.Println("  No DNS configuration needed!")
		fmt.Println("  Your email address is ready to use.")
		fmt.Println("========================================")
		fmt.Println()

		db.LogAudit("cli", "subdomain.create", alloc.FQDN)

	default:
		fmt.Fprintf(os.Stderr, "unknown subdomain command: %s\n", args[0])
		os.Exit(1)
	}
}

func generateAliasAddr(domain string) string {
	// Simple random alias generation
	b := make([]byte, 8)
	f, _ := os.Open("/dev/urandom")
	f.Read(b)
	f.Close()
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 12)
	for i := range result {
		result[i] = chars[int(b[i%len(b)])%len(chars)]
	}
	return string(result) + "@" + domain
}
