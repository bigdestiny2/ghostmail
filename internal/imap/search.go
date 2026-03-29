package imap

import (
	"bytes"
	"fmt"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/ghostmail/ghostmail/internal/storage"
)

func (s *Session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	if s.selectedMailbox == nil {
		return nil, fmt.Errorf("no mailbox selected")
	}

	msgs, err := s.db.ListMessages(s.selectedMailbox.ID)
	if err != nil {
		return nil, err
	}

	var allNums []uint32
	for i, msg := range msgs {
		if matchesCriteria(msg, criteria) {
			switch kind {
			case imapserver.NumKindSeq:
				allNums = append(allNums, uint32(i+1))
			case imapserver.NumKindUID:
				allNums = append(allNums, uint32(msg.UID))
			}
		}
	}

	data := &imap.SearchData{}

	if options != nil && options.ReturnCount {
		data.Count = uint32(len(allNums))
	}

	if options != nil && options.ReturnMin && len(allNums) > 0 {
		data.Min = allNums[0]
	}

	if options != nil && options.ReturnMax && len(allNums) > 0 {
		data.Max = allNums[len(allNums)-1]
	}

	// Build a NumSet for All results
	if options == nil || options.ReturnAll || (!options.ReturnCount && !options.ReturnMin && !options.ReturnMax) {
		switch kind {
		case imapserver.NumKindUID:
			uidSet := imap.UIDSet{}
			for _, n := range allNums {
				uidSet.AddNum(imap.UID(n))
			}
			data.All = uidSet
		case imapserver.NumKindSeq:
			seqSet := imap.SeqSet{}
			for _, n := range allNums {
				seqSet.AddNum(n)
			}
			data.All = seqSet
		}
	}

	return data, nil
}

// matchesCriteria checks if a message matches the given search criteria.
// Phase 1: plaintext matching. Phase 3 will use the encrypted blind index.
func matchesCriteria(msg *storage.Message, criteria *imap.SearchCriteria) bool {
	if criteria == nil {
		return true
	}

	// Flag criteria
	for _, flag := range criteria.Flag {
		if !storage.HasFlag(msg.Flags, string(flag)) {
			return false
		}
	}
	for _, flag := range criteria.NotFlag {
		if storage.HasFlag(msg.Flags, string(flag)) {
			return false
		}
	}

	// Date criteria (internal date)
	if !criteria.Since.IsZero() && msg.InternalDate.Before(criteria.Since) {
		return false
	}
	if !criteria.Before.IsZero() && !msg.InternalDate.Before(criteria.Before) {
		return false
	}

	// Sent date criteria
	if !criteria.SentSince.IsZero() {
		sentDate := extractDate(msg.BodyEnc)
		if sentDate.Before(criteria.SentSince) {
			return false
		}
	}
	if !criteria.SentBefore.IsZero() {
		sentDate := extractDate(msg.BodyEnc)
		if !sentDate.Before(criteria.SentBefore) {
			return false
		}
	}

	// Size criteria
	if criteria.Larger > 0 && int64(msg.Size) <= criteria.Larger {
		return false
	}
	if criteria.Smaller > 0 && int64(msg.Size) >= criteria.Smaller {
		return false
	}

	// UID criteria (slice of UIDSets)
	if len(criteria.UID) > 0 {
		matched := false
		for _, uidSet := range criteria.UID {
			if uidSet.Contains(imap.UID(msg.UID)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Header criteria
	for _, hdr := range criteria.Header {
		if !headerContainsValue(msg.BodyEnc, hdr.Key, hdr.Value) {
			return false
		}
	}

	// Body text search (Phase 1: brute force through plaintext)
	for _, text := range criteria.Body {
		if !bytes.Contains(msg.BodyEnc, []byte(text)) {
			return false
		}
	}

	// Text search (headers + body)
	for _, text := range criteria.Text {
		if !bytes.Contains(msg.BodyEnc, []byte(text)) {
			return false
		}
	}

	// NOT criteria
	for _, sub := range criteria.Not {
		if matchesCriteria(msg, &sub) {
			return false
		}
	}

	// OR criteria
	for _, orPair := range criteria.Or {
		if !matchesCriteria(msg, &orPair[0]) && !matchesCriteria(msg, &orPair[1]) {
			return false
		}
	}

	return true
}

// extractDate parses the Date header from a message.
func extractDate(data []byte) time.Time {
	dateStr := getHeaderValue(data, "Date")
	if dateStr == "" {
		return time.Time{}
	}
	for _, format := range []string{
		time.RFC1123Z,
		time.RFC1123,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 -0700",
	} {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}
	return time.Time{}
}
