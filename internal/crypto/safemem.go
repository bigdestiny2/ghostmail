// Package crypto provides all cryptographic operations for GhostMail.
package crypto

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Wipe zeroes a byte slice to remove sensitive key material from memory.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Prevent compiler from optimizing away the zeroing
	runtime.KeepAlive(b)
}

// WipeKey zeroes a fixed-size key array.
func WipeKey(k *[32]byte) {
	for i := range k {
		k[i] = 0
	}
	runtime.KeepAlive(k)
}

// Mlock attempts to lock memory pages containing the given byte slice,
// preventing them from being swapped to disk. This is best-effort;
// failures are silently ignored (e.g., if mlock limits are exceeded).
func Mlock(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Mlock(b)
}

// Munlock unlocks previously locked memory pages.
func Munlock(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Munlock(b)
}

// LockedKey allocates a 32-byte key in locked memory.
// The caller must call Release() when done.
type LockedKey struct {
	Key [32]byte
}

// NewLockedKey creates a new LockedKey with locked memory pages.
func NewLockedKey() *LockedKey {
	k := &LockedKey{}
	Mlock(k.Key[:])
	return k
}

// Release zeroes and unlocks the key memory.
func (k *LockedKey) Release() {
	WipeKey(&k.Key)
	Munlock(k.Key[:])
}

// Bytes returns the key as a byte slice.
func (k *LockedKey) Bytes() []byte {
	return k.Key[:]
}

// LockedBuffer allocates a variable-size buffer in locked memory.
type LockedBuffer struct {
	data []byte
}

// NewLockedBuffer creates a buffer of the given size in locked memory.
func NewLockedBuffer(size int) *LockedBuffer {
	buf := &LockedBuffer{data: make([]byte, size)}
	Mlock(buf.data)
	return buf
}

// Release zeroes and unlocks the buffer.
func (b *LockedBuffer) Release() {
	Wipe(b.data)
	Munlock(b.data)
}

// Bytes returns the buffer contents.
func (b *LockedBuffer) Bytes() []byte {
	return b.data
}

// Size returns the buffer length.
func (b *LockedBuffer) Size() int {
	return len(b.data)
}

// ConstantTimeEqual compares two byte slices in constant time.
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// Ensure unsafe is used (for future madvise calls if needed)
var _ = unsafe.Pointer(nil)
