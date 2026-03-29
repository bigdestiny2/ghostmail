package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"unicode"
)

// Search field types for the blind index.
const (
	FieldSubject = 0
	FieldFrom    = 1
	FieldTo      = 2
	FieldBody    = 3
)

// SearchToken represents a single blind index entry.
type SearchToken struct {
	TokenHash []byte // HMAC-SHA256(searchKey, normalizedTerm)
	Field     int    // Which field this token came from
}

// GenerateSearchTokens creates blind index tokens for a message.
// The searchKey is the user's HKDF-derived search sub-key.
func GenerateSearchTokens(searchKey []byte, subject, from, to, body string) []SearchToken {
	var tokens []SearchToken

	// Tokenize each field
	for _, term := range tokenize(subject) {
		tokens = append(tokens, SearchToken{
			TokenHash: computeTokenHash(searchKey, term),
			Field:     FieldSubject,
		})
	}
	for _, term := range tokenize(from) {
		tokens = append(tokens, SearchToken{
			TokenHash: computeTokenHash(searchKey, term),
			Field:     FieldFrom,
		})
	}
	for _, term := range tokenize(to) {
		tokens = append(tokens, SearchToken{
			TokenHash: computeTokenHash(searchKey, term),
			Field:     FieldTo,
		})
	}
	for _, term := range tokenize(body) {
		tokens = append(tokens, SearchToken{
			TokenHash: computeTokenHash(searchKey, term),
			Field:     FieldBody,
		})
	}

	return dedup(tokens)
}

// ComputeSearchQuery creates a token hash for a search term,
// used to query the blind index.
func ComputeSearchQuery(searchKey []byte, term string) []byte {
	normalized := normalize(term)
	return computeTokenHash(searchKey, normalized)
}

// computeTokenHash computes HMAC-SHA256(key, term).
func computeTokenHash(key []byte, term string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(term))
	return mac.Sum(nil)
}

// tokenize splits text into normalized search terms.
func tokenize(text string) []string {
	if text == "" {
		return nil
	}

	// Split on whitespace and punctuation
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '@' && r != '.'
	})

	seen := make(map[string]struct{})
	var result []string
	for _, w := range words {
		w = normalize(w)
		if w == "" || len(w) < 2 {
			continue
		}
		// Skip common stop words
		if isStopWord(w) {
			continue
		}
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		result = append(result, w)
	}
	return result
}

// normalize lowercases and trims a term.
func normalize(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

// isStopWord returns true for common English stop words.
func isStopWord(w string) bool {
	stops := map[string]struct{}{
		"the": {}, "a": {}, "an": {}, "is": {}, "are": {}, "was": {},
		"were": {}, "be": {}, "been": {}, "being": {}, "have": {},
		"has": {}, "had": {}, "do": {}, "does": {}, "did": {},
		"will": {}, "would": {}, "could": {}, "should": {},
		"may": {}, "might": {}, "shall": {}, "can": {},
		"to": {}, "of": {}, "in": {}, "for": {}, "on": {},
		"with": {}, "at": {}, "by": {}, "from": {}, "as": {},
		"it": {}, "its": {}, "this": {}, "that": {}, "or": {},
		"and": {}, "but": {}, "if": {}, "not": {},
	}
	_, ok := stops[w]
	return ok
}

// dedup removes duplicate tokens (same hash + field).
func dedup(tokens []SearchToken) []SearchToken {
	type key struct {
		hash  string
		field int
	}
	seen := make(map[key]struct{})
	var result []SearchToken
	for _, t := range tokens {
		k := key{hash: string(t.TokenHash), field: t.Field}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		result = append(result, t)
	}
	return result
}
