package crypto

import (
	"fmt"
)

// Service provides high-level cryptographic operations for GhostMail.
// It holds server-wide configuration but no per-user state.
type Service struct {
	argon2Time    uint32
	argon2Memory  uint32
	argon2Threads uint8
}

// NewService creates a new crypto service with the given Argon2id parameters.
func NewService(time, memory uint32, threads uint8) *Service {
	return &Service{
		argon2Time:    time,
		argon2Memory:  memory,
		argon2Threads: threads,
	}
}

// UserKeys holds all crypto material for a user registration.
type UserKeys struct {
	PublicKey         []byte // X25519 public key (stored in DB)
	WrappedPrivateKey []byte // Private key encrypted with encryption sub-key
	KeyNonce          []byte // Nonce for wrapped private key
	AuthHash          []byte // Argon2id-derived auth hash (stored as password_hash)
	KeyParams         string // JSON-encoded KeyParams
	SearchKey         []byte // Search sub-key (encrypted with server indexing key)
}

// RegisterUser generates all cryptographic material for a new user.
// Returns the keys to store in the database.
func (s *Service) RegisterUser(password []byte) (*UserKeys, error) {
	// Generate Argon2id params with random salt
	params, err := DefaultKeyParams(s.argon2Time, s.argon2Memory, s.argon2Threads)
	if err != nil {
		return nil, fmt.Errorf("creating key params: %w", err)
	}

	// Derive the full key hierarchy
	dk, err := DeriveFromPassword(password, params)
	if err != nil {
		return nil, fmt.Errorf("deriving keys: %w", err)
	}
	defer dk.Release()

	// Generate X25519 keypair
	pubKey, privKey, err := GenerateX25519Keypair()
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}
	defer Wipe(privKey)

	// Wrap private key with the encryption sub-key
	wrappedPriv, privNonce, err := WrapPrivateKey(privKey, dk.EncryptionKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("wrapping private key: %w", err)
	}

	// Copy auth hash (will be stored as password_hash)
	authHash := make([]byte, 32)
	copy(authHash, dk.AuthKey.Bytes())

	// Copy search key (stored for server-side indexing)
	searchKey := make([]byte, 32)
	copy(searchKey, dk.SearchKey.Bytes())

	return &UserKeys{
		PublicKey:         pubKey,
		WrappedPrivateKey: wrappedPriv,
		KeyNonce:          privNonce,
		AuthHash:          authHash,
		KeyParams:         MarshalKeyParams(params),
		SearchKey:         searchKey,
	}, nil
}

// AuthenticateUser verifies a password and returns the decrypted private key
// and search key for use during the session.
type SessionKeys struct {
	PrivateKey []byte // Decrypted X25519 private key (hold in locked memory)
	SearchKey  []byte // Search HMAC key
}

// Authenticate verifies a password and derives session keys.
func (s *Service) Authenticate(password []byte, keyParamsJSON string,
	storedAuthHash []byte, wrappedPrivateKey, keyNonce []byte) (*SessionKeys, error) {

	params, err := UnmarshalKeyParams(keyParamsJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing key params: %w", err)
	}

	dk, err := DeriveFromPassword(password, params)
	if err != nil {
		return nil, fmt.Errorf("deriving keys: %w", err)
	}
	defer dk.Release()

	// Verify password via auth hash
	if !ConstantTimeEqual(dk.AuthKey.Bytes(), storedAuthHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Unwrap private key
	privKey, err := UnwrapPrivateKey(wrappedPrivateKey, keyNonce, dk.EncryptionKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("unwrapping private key: %w", err)
	}

	// Copy search key
	searchKey := make([]byte, 32)
	copy(searchKey, dk.SearchKey.Bytes())

	return &SessionKeys{
		PrivateKey: privKey,
		SearchKey:  searchKey,
	}, nil
}

// Release zeroes session key material.
func (sk *SessionKeys) Release() {
	if sk.PrivateKey != nil {
		Wipe(sk.PrivateKey)
	}
	if sk.SearchKey != nil {
		Wipe(sk.SearchKey)
	}
}

// UserKeysWithVault holds crypto material for a vault-enabled user registration.
// Auth password and vault password are independent.
type UserKeysWithVault struct {
	// Auth-only fields (derived from auth password)
	AuthHash  []byte // Stored as password_hash for IMAP/SMTP login verification
	KeyParams string // Argon2id params for the auth password

	// Vault fields (derived from vault password)
	VaultHash            []byte // Stored as vault_hash for vault unlock verification
	VaultKeyParams       string // Argon2id params for the vault password
	VaultWrappedPrivKey  []byte // Private key encrypted with vault encryption sub-key
	VaultKeyNonce        []byte // Nonce for vault-wrapped private key

	// Shared fields
	PublicKey  []byte // X25519 public key (used by senders to encrypt to this user)
	SearchKey  []byte // Search HMAC key (derived from vault password)
}

// RegisterUserWithVault generates crypto material using two independent passwords.
// The auth password only proves identity. The vault password unlocks decryption.
func (s *Service) RegisterUserWithVault(authPassword, vaultPassword []byte) (*UserKeysWithVault, error) {
	// --- Auth password: derive only an auth hash ---
	authParams, err := DefaultKeyParams(s.argon2Time, s.argon2Memory, s.argon2Threads)
	if err != nil {
		return nil, fmt.Errorf("creating auth key params: %w", err)
	}
	authDK, err := DeriveFromPassword(authPassword, authParams)
	if err != nil {
		return nil, fmt.Errorf("deriving auth keys: %w", err)
	}
	authHash := make([]byte, 32)
	copy(authHash, authDK.AuthKey.Bytes())
	authDK.Release()

	// --- Vault password: derive encryption key + search key, wrap private key ---
	vaultParams, err := DefaultKeyParams(s.argon2Time, s.argon2Memory, s.argon2Threads)
	if err != nil {
		return nil, fmt.Errorf("creating vault key params: %w", err)
	}
	vaultDK, err := DeriveFromPassword(vaultPassword, vaultParams)
	if err != nil {
		return nil, fmt.Errorf("deriving vault keys: %w", err)
	}
	defer vaultDK.Release()

	// Generate X25519 keypair
	pubKey, privKey, err := GenerateX25519Keypair()
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}
	defer Wipe(privKey)

	// Wrap private key with the vault encryption sub-key
	wrappedPriv, privNonce, err := WrapPrivateKey(privKey, vaultDK.EncryptionKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("wrapping private key with vault key: %w", err)
	}

	// Vault auth hash for verification
	vaultHash := make([]byte, 32)
	copy(vaultHash, vaultDK.AuthKey.Bytes())

	// Search key from vault derivation
	searchKey := make([]byte, 32)
	copy(searchKey, vaultDK.SearchKey.Bytes())

	return &UserKeysWithVault{
		AuthHash:            authHash,
		KeyParams:           MarshalKeyParams(authParams),
		VaultHash:           vaultHash,
		VaultKeyParams:      MarshalKeyParams(vaultParams),
		VaultWrappedPrivKey: wrappedPriv,
		VaultKeyNonce:       privNonce,
		PublicKey:           pubKey,
		SearchKey:           searchKey,
	}, nil
}

// AuthenticateAuthOnly verifies only the auth password without deriving decryption keys.
// Used for IMAP/SMTP login of vault-enabled users.
func (s *Service) AuthenticateAuthOnly(password []byte, keyParamsJSON string, storedAuthHash []byte) error {
	params, err := UnmarshalKeyParams(keyParamsJSON)
	if err != nil {
		return fmt.Errorf("parsing key params: %w", err)
	}
	dk, err := DeriveFromPassword(password, params)
	if err != nil {
		return fmt.Errorf("deriving keys: %w", err)
	}
	defer dk.Release()

	if !ConstantTimeEqual(dk.AuthKey.Bytes(), storedAuthHash) {
		return fmt.Errorf("invalid credentials")
	}
	return nil
}

// UnlockVault verifies the vault password and returns decrypted session keys.
func (s *Service) UnlockVault(vaultPassword []byte, vaultKeyParamsJSON string,
	storedVaultHash []byte, vaultWrappedPrivKey, vaultKeyNonce []byte) (*SessionKeys, error) {

	params, err := UnmarshalKeyParams(vaultKeyParamsJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing vault key params: %w", err)
	}
	dk, err := DeriveFromPassword(vaultPassword, params)
	if err != nil {
		return nil, fmt.Errorf("deriving vault keys: %w", err)
	}
	defer dk.Release()

	// Verify vault password
	if !ConstantTimeEqual(dk.AuthKey.Bytes(), storedVaultHash) {
		return nil, fmt.Errorf("invalid vault password")
	}

	// Unwrap private key
	privKey, err := UnwrapPrivateKey(vaultWrappedPrivKey, vaultKeyNonce, dk.EncryptionKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("unwrapping private key: %w", err)
	}

	// Copy search key
	searchKey := make([]byte, 32)
	copy(searchKey, dk.SearchKey.Bytes())

	return &SessionKeys{
		PrivateKey: privKey,
		SearchKey:  searchKey,
	}, nil
}
