package storage

import (
	"bytes"
	"fmt"
)

// StoreSearchTokens inserts blind index tokens for a message.
func (db *DB) StoreSearchTokens(messageID int64, tokens []SearchToken) error {
	if len(tokens) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO search_tokens (message_id, token_hash, field) VALUES (?, ?, ?)")
	if err != nil {
		return fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	for _, tok := range tokens {
		if _, err := stmt.Exec(messageID, tok.Hash, tok.Field); err != nil {
			return fmt.Errorf("inserting token: %w", err)
		}
	}

	return tx.Commit()
}

// SearchToken is the storage representation of a blind index entry.
type SearchToken struct {
	Hash  []byte
	Field int
}

// SearchByToken finds message IDs matching a token hash, optionally filtered by field.
func (db *DB) SearchByToken(tokenHash []byte, field int) ([]int64, error) {
	var rows_result []int64

	if field >= 0 {
		rows, err := db.Query(
			"SELECT DISTINCT message_id FROM search_tokens WHERE token_hash = ? AND field = ?",
			tokenHash, field)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			rows_result = append(rows_result, id)
		}
		return rows_result, rows.Err()
	}

	rows, err := db.Query(
		"SELECT DISTINCT message_id FROM search_tokens WHERE token_hash = ?",
		tokenHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		rows_result = append(rows_result, id)
	}
	return rows_result, rows.Err()
}

// SearchByTokens finds message IDs matching ALL given token hashes (AND query).
func (db *DB) SearchByTokens(tokenHashes [][]byte) ([]int64, error) {
	if len(tokenHashes) == 0 {
		return nil, nil
	}

	// Get results for the first token
	results, err := db.SearchByToken(tokenHashes[0], -1)
	if err != nil {
		return nil, err
	}

	// Intersect with results for subsequent tokens
	for _, hash := range tokenHashes[1:] {
		next, err := db.SearchByToken(hash, -1)
		if err != nil {
			return nil, err
		}
		results = intersect(results, next)
		if len(results) == 0 {
			break
		}
	}

	return results, nil
}

// DeleteSearchTokens removes all tokens for a message.
func (db *DB) DeleteSearchTokens(messageID int64) error {
	_, err := db.Exec("DELETE FROM search_tokens WHERE message_id = ?", messageID)
	return err
}

func intersect(a, b []int64) []int64 {
	set := make(map[int64]struct{}, len(b))
	for _, v := range b {
		set[v] = struct{}{}
	}
	var result []int64
	for _, v := range a {
		if _, ok := set[v]; ok {
			result = append(result, v)
		}
	}
	return result
}

// TokensContain checks if any stored token matches a given hash.
func TokensContain(tokens []SearchToken, hash []byte) bool {
	for _, tok := range tokens {
		if bytes.Equal(tok.Hash, hash) {
			return true
		}
	}
	return false
}
