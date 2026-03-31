package imap

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
)

func (s *Session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	if s.selectedMailbox == nil {
		return fmt.Errorf("no mailbox selected")
	}

	msgs, err := s.db.ListMessages(s.selectedMailbox.ID)
	if err != nil {
		return err
	}

	matching := resolveNumSet(msgs, numSet)

	for seqNum, msg := range matching {
		// Dynamically pick up vault unlock if it happened mid-session
		if s.sessionKeys == nil && s.vaultStore != nil && s.user != nil {
			if vs := s.vaultStore.GetByUser(s.user.ID); vs != nil {
				s.sessionKeys = vs.Keys
			}
		}

		// Decrypt message body on-the-fly if encrypted
		messageData := msg.BodyEnc
		if s.sessionKeys != nil && len(msg.MessageKeyEnc) > 0 {
			plaintext, err := crypto.DecryptMessage(
				msg.BodyEnc, msg.BodyNonce,
				msg.MessageKeyEnc, msg.MessageKeyNonce,
				s.sessionKeys.PrivateKey,
			)
			if err != nil {
				s.logger.Error("message decryption failed", "uid", msg.UID, "error", err)
				// Fall back to encrypted data (client will see garbage)
			} else {
				messageData = plaintext
			}
		}

		respWriter := w.CreateMessage(seqNum)

		if options.UID {
			respWriter.WriteUID(imap.UID(msg.UID))
		}

		if options.Flags {
			respWriter.WriteFlags(parseFlags(msg.Flags))
		}

		if options.RFC822Size {
			respWriter.WriteRFC822Size(int64(msg.Size))
		}

		if options.InternalDate {
			respWriter.WriteInternalDate(msg.InternalDate)
		}

		if options.Envelope {
			h := parseMessageHeader(messageData)
			env := imapserver.ExtractEnvelope(h)
			respWriter.WriteEnvelope(env)
		}

		if options.BodyStructure != nil {
			r := bytes.NewReader(messageData)
			bs := imapserver.ExtractBodyStructure(r)
			respWriter.WriteBodyStructure(bs)
		}

		for _, bs := range options.BodySection {
			body := imapserver.ExtractBodySection(bytes.NewReader(messageData), bs)
			wc := respWriter.WriteBodySection(bs, int64(len(body)))
			wc.Write(body)
			wc.Close()
		}

		for _, bs := range options.BinarySection {
			body := imapserver.ExtractBinarySection(bytes.NewReader(messageData), bs)
			wc := respWriter.WriteBinarySection(bs, int64(len(body)))
			wc.Write(body)
			wc.Close()
		}

		for _, bs := range options.BinarySectionSize {
			size := imapserver.ExtractBinarySectionSize(bytes.NewReader(messageData), bs)
			respWriter.WriteBinarySectionSize(bs, size)
		}

		if err := respWriter.Close(); err != nil {
			return err
		}

		// Auto-set \Seen flag on FETCH with body sections (unless PEEK)
		if len(options.BodySection) > 0 && !allPeek(options.BodySection) {
			if !storage.HasFlag(msg.Flags, "\\Seen") {
				newFlags := storage.AddFlag(msg.Flags, "\\Seen")
				s.db.UpdateFlags(msg.ID, newFlags)
			}
		}
	}

	return nil
}

func (s *Session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	if s.selectedMailbox == nil {
		return fmt.Errorf("no mailbox selected")
	}

	msgs, err := s.db.ListMessages(s.selectedMailbox.ID)
	if err != nil {
		return err
	}

	matching := resolveNumSet(msgs, numSet)

	for seqNum, msg := range matching {
		newFlagStr := applyStoreFlags(msg.Flags, flags)
		if err := s.db.UpdateFlags(msg.ID, newFlagStr); err != nil {
			return err
		}

		// Notify other sessions of flag change
		if s.sessionTracker != nil {
			tracker := s.server.GetTracker(s.selectedMailbox.ID, 0)
			tracker.QueueMessageFlags(seqNum, imap.UID(msg.UID), parseFlags(newFlagStr), s.sessionTracker)
		}

		// Write the FETCH response unless SILENT
		if !flags.Silent {
			respWriter := w.CreateMessage(seqNum)
			respWriter.WriteUID(imap.UID(msg.UID))
			respWriter.WriteFlags(parseFlags(newFlagStr))
			if err := respWriter.Close(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if s.selectedMailbox == nil {
		return fmt.Errorf("no mailbox selected")
	}

	msgs, err := s.db.ListMessages(s.selectedMailbox.ID)
	if err != nil {
		return err
	}

	// Delete messages with \Deleted flag, in reverse order (high to low seq num)
	// to keep sequence numbers stable
	deleted := 0
	for i := len(msgs) - 1; i >= 0; i-- {
		msg := msgs[i]

		if !storage.HasFlag(msg.Flags, "\\Deleted") {
			continue
		}

		// If UIDs specified, check if this message is in the set
		if uids != nil && !uids.Contains(imap.UID(msg.UID)) {
			continue
		}

		seqNum := uint32(i + 1 - deleted)
		if err := s.db.DeleteMessage(msg.ID); err != nil {
			return err
		}

		if err := w.WriteExpunge(seqNum); err != nil {
			return err
		}
		deleted++
	}

	return nil
}

func (s *Session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	if s.selectedMailbox == nil {
		return nil, fmt.Errorf("no mailbox selected")
	}
	if s.user == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	destMb, err := s.db.GetMailbox(s.user.ID, dest)
	if err != nil {
		return nil, err
	}
	if destMb == nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTryCreate,
			Text: "destination mailbox does not exist",
		}
	}

	msgs, err := s.db.ListMessages(s.selectedMailbox.ID)
	if err != nil {
		return nil, err
	}

	matching := resolveNumSet(msgs, numSet)

	var srcUIDs, destUIDs []imap.UID
	for _, msg := range matching {
		newMsg := &storage.Message{
			MailboxID:       destMb.ID,
			MessageKeyEnc:   msg.MessageKeyEnc,
			MessageKeyNonce: msg.MessageKeyNonce,
			HeaderEnc:       msg.HeaderEnc,
			HeaderNonce:     msg.HeaderNonce,
			BodyEnc:         msg.BodyEnc,
			BodyNonce:       msg.BodyNonce,
			Size:            msg.Size,
			Flags:           msg.Flags,
			InternalDate:    msg.InternalDate,
			ExpiresAt:       msg.ExpiresAt,
			EnvelopeEnc:     msg.EnvelopeEnc,
			EnvelopeNonce:   msg.EnvelopeNonce,
		}
		if err := s.db.StoreMessage(newMsg); err != nil {
			return nil, err
		}
		srcUIDs = append(srcUIDs, imap.UID(msg.UID))
		destUIDs = append(destUIDs, imap.UID(newMsg.UID))
	}

	// Notify watchers of dest mailbox
	newCount, _ := s.db.MailboxMessageCount(destMb.ID)
	s.server.NotifyNewMessage(destMb.ID, uint32(newCount))

	srcSet := imap.UIDSet{}
	destSet := imap.UIDSet{}
	for i := range srcUIDs {
		srcSet.AddNum(srcUIDs[i])
		destSet.AddNum(destUIDs[i])
	}

	return &imap.CopyData{
		UIDValidity: uint32(destMb.UIDValidity),
		SourceUIDs:  srcSet,
		DestUIDs:    destSet,
	}, nil
}

func (s *Session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	copyData, err := s.Copy(numSet, dest)
	if err != nil {
		return err
	}

	if err := w.WriteCopyData(copyData); err != nil {
		return err
	}

	// Expunge the source messages
	msgs, err := s.db.ListMessages(s.selectedMailbox.ID)
	if err != nil {
		return err
	}

	matching := resolveNumSet(msgs, numSet)

	// Collect and sort sequence numbers descending for stable expunge
	seqNums := make([]uint32, 0, len(matching))
	for seqNum := range matching {
		seqNums = append(seqNums, seqNum)
	}
	sort.Slice(seqNums, func(i, j int) bool { return seqNums[i] > seqNums[j] })

	for _, seqNum := range seqNums {
		msg := matching[seqNum]
		if err := s.db.DeleteMessage(msg.ID); err != nil {
			return err
		}
		if err := w.WriteExpunge(seqNum); err != nil {
			return err
		}
	}

	return nil
}

// --- Helpers ---

// resolveNumSet maps a NumSet to a map of sequence_number -> message.
func resolveNumSet(msgs []*storage.Message, numSet imap.NumSet) map[uint32]*storage.Message {
	result := make(map[uint32]*storage.Message)

	switch set := numSet.(type) {
	case imap.SeqSet:
		for i, msg := range msgs {
			seqNum := uint32(i + 1)
			if set.Contains(seqNum) {
				result[seqNum] = msg
			}
		}
	case imap.UIDSet:
		for i, msg := range msgs {
			if set.Contains(imap.UID(msg.UID)) {
				result[uint32(i + 1)] = msg
			}
		}
	}

	return result
}

// parseFlags converts a space-separated flag string to a slice of imap.Flag.
func parseFlags(s string) []imap.Flag {
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	flags := make([]imap.Flag, len(parts))
	for i, p := range parts {
		flags[i] = imap.Flag(p)
	}
	return flags
}

// applyStoreFlags applies STORE flag operations.
func applyStoreFlags(current string, sf *imap.StoreFlags) string {
	switch sf.Op {
	case imap.StoreFlagsSet:
		flagStrs := make([]string, len(sf.Flags))
		for i, ff := range sf.Flags {
			flagStrs[i] = string(ff)
		}
		return strings.Join(flagStrs, " ")
	case imap.StoreFlagsAdd:
		for _, f := range sf.Flags {
			current = storage.AddFlag(current, string(f))
		}
	case imap.StoreFlagsDel:
		for _, f := range sf.Flags {
			current = storage.RemoveFlag(current, string(f))
		}
	}
	return current
}

// allPeek returns true if all body sections use PEEK.
func allPeek(sections []*imap.FetchItemBodySection) bool {
	for _, s := range sections {
		if !s.Peek {
			return false
		}
	}
	return true
}
