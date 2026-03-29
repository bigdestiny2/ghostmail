package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// KeyParams holds Argon2id parameters for key derivation.
type KeyParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`  // in KB
	Threads uint8  `json:"threads"`
	Salt    []byte `json:"salt"`    // 32 bytes
}

// DefaultKeyParams returns the default Argon2id parameters.
func DefaultKeyParams(time uint32, memory uint32, threads uint8) (*KeyParams, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	return &KeyParams{
		Time:    time,
		Memory:  memory,
		Threads: threads,
		Salt:    salt,
	}, nil
}

// MarshalKeyParams serializes key params to JSON.
func MarshalKeyParams(kp *KeyParams) string {
	data, _ := json.Marshal(kp)
	return string(data)
}

// UnmarshalKeyParams deserializes key params from JSON.
func UnmarshalKeyParams(s string) (*KeyParams, error) {
	kp := &KeyParams{}
	if err := json.Unmarshal([]byte(s), kp); err != nil {
		return nil, fmt.Errorf("parsing key params: %w", err)
	}
	return kp, nil
}

// DeriveKeys derives the full key hierarchy from a user password.
//
// Password --> Argon2id --> MasterKey (32 bytes)
//   |-> HKDF("auth")       --> AuthKey (for password verification)
//   |-> HKDF("encryption") --> EncryptionKey (for unwrapping private key)
//   |-> HKDF("search")     --> SearchKey (for blind index HMAC)
type DerivedKeys struct {
	MasterKey     *LockedKey
	AuthKey       *LockedKey
	EncryptionKey *LockedKey
	SearchKey     *LockedKey
}

// DeriveFromPassword derives the full key hierarchy from a password.
// The caller must call Release() when done with the keys.
func DeriveFromPassword(password []byte, params *KeyParams) (*DerivedKeys, error) {
	// Argon2id: password + salt -> 32-byte master key
	masterRaw := argon2.IDKey(password, params.Salt, params.Time, params.Memory, params.Threads, 32)

	dk := &DerivedKeys{
		MasterKey:     NewLockedKey(),
		AuthKey:       NewLockedKey(),
		EncryptionKey: NewLockedKey(),
		SearchKey:     NewLockedKey(),
	}
	copy(dk.MasterKey.Key[:], masterRaw)
	Wipe(masterRaw)

	// Derive sub-keys via HKDF-SHA256
	if err := deriveSubKey(dk.MasterKey.Bytes(), "ghostmail-auth", &dk.AuthKey.Key); err != nil {
		dk.Release()
		return nil, fmt.Errorf("deriving auth key: %w", err)
	}
	if err := deriveSubKey(dk.MasterKey.Bytes(), "ghostmail-encryption", &dk.EncryptionKey.Key); err != nil {
		dk.Release()
		return nil, fmt.Errorf("deriving encryption key: %w", err)
	}
	if err := deriveSubKey(dk.MasterKey.Bytes(), "ghostmail-search", &dk.SearchKey.Key); err != nil {
		dk.Release()
		return nil, fmt.Errorf("deriving search key: %w", err)
	}

	return dk, nil
}

// Release zeroes all key material.
func (dk *DerivedKeys) Release() {
	if dk.MasterKey != nil {
		dk.MasterKey.Release()
	}
	if dk.AuthKey != nil {
		dk.AuthKey.Release()
	}
	if dk.EncryptionKey != nil {
		dk.EncryptionKey.Release()
	}
	if dk.SearchKey != nil {
		dk.SearchKey.Release()
	}
}

// deriveSubKey uses HKDF-SHA256 to derive a 32-byte sub-key.
func deriveSubKey(masterKey []byte, info string, out *[32]byte) error {
	hk := hkdf.New(sha256.New, masterKey, nil, []byte(info))
	if _, err := io.ReadFull(hk, out[:]); err != nil {
		return err
	}
	return nil
}

// HashPassword creates an Argon2id-based password hash for storage.
// Returns the auth sub-key which is stored as the verification hash.
func HashPassword(password []byte, params *KeyParams) ([]byte, error) {
	dk, err := DeriveFromPassword(password, params)
	if err != nil {
		return nil, err
	}
	defer dk.Release()

	// Return a copy of the auth key (the original will be wiped)
	authHash := make([]byte, 32)
	copy(authHash, dk.AuthKey.Bytes())
	return authHash, nil
}

// VerifyPassword checks a password against a stored auth hash.
func VerifyPassword(password []byte, params *KeyParams, storedHash []byte) bool {
	dk, err := DeriveFromPassword(password, params)
	if err != nil {
		return false
	}
	defer dk.Release()

	return ConstantTimeEqual(dk.AuthKey.Bytes(), storedHash)
}

// GenerateRandom generates cryptographically random bytes.
func GenerateRandom(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
