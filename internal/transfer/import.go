package transfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/protocol"
	"github.com/ardasevinc/pa/internal/store"
)

type ImportResult struct {
	TransactionID string `json:"transaction_id"`
	BundleEntries uint32 `json:"bundle_entries"`
	Imported      int    `json:"imported"`
	Skipped       int    `json:"skipped"`
	BackupBefore  string `json:"backup_before,omitempty"`
	BackupAfter   string `json:"backup_after,omitempty"`
	Receipt       string `json:"receipt,omitempty"`
	GitCommitted  bool   `json:"git_committed"`
	Partial       bool   `json:"partial"`
}

type AppliedError struct {
	Result ImportResult
	Err    error
}

func (e *AppliedError) Error() string {
	return fmt.Sprintf("password entries were applied but finalization failed: %v", e.Err)
}

func (e *AppliedError) Unwrap() error {
	return e.Err
}

type stagedEntry struct {
	name   string
	size   uint64
	digest [sha256.Size]byte
}

type activeEntry struct {
	name    string
	skipped bool
	writer  *agecmd.EncryptWriter
	path    string
}

type stagingConsumer struct {
	ctx         context.Context
	age         agecmd.Tool
	store       *store.Store
	transaction *store.Transaction
	active      *activeEntry
	staged      []stagedEntry
	skipped     int
}

func (c *stagingConsumer) BeginEntry(name string) (io.Writer, error) {
	if c.active != nil {
		return nil, errors.New("previous staged entry is still active")
	}
	exists, err := c.store.Exists(name)
	if err != nil {
		return nil, err
	}
	if exists {
		c.active = &activeEntry{name: name, skipped: true}
		c.skipped++
		return io.Discard, nil
	}

	_, absolutePath, err := c.transaction.StagePath(name)
	if err != nil {
		return nil, err
	}
	writer, err := c.age.StartEncrypt(c.ctx, c.store.RecipientsPath, absolutePath)
	if err != nil {
		return nil, err
	}
	c.active = &activeEntry{name: name, writer: writer, path: absolutePath}
	return writer, nil
}

func (c *stagingConsumer) EndEntry(name string, size uint64, digest [sha256.Size]byte) error {
	if c.active == nil || c.active.name != name {
		return fmt.Errorf("staging state mismatch for %q", name)
	}
	active := c.active
	c.active = nil
	if active.skipped {
		return nil
	}
	if err := active.writer.Close(); err != nil {
		return err
	}

	actualSize, actualDigest, err := plaintextDigest(c.ctx, c.age, c.store.IdentitiesPath, active.path)
	if err != nil {
		return fmt.Errorf("verify staged entry %q: %w", name, err)
	}
	if actualSize != size || actualDigest != digest {
		return fmt.Errorf("verify staged entry %q: plaintext mismatch", name)
	}
	c.staged = append(c.staged, stagedEntry{name: name, size: size, digest: digest})
	return nil
}

func (c *stagingConsumer) Abort() {
	if c.active != nil && c.active.writer != nil {
		_ = c.active.writer.Abort()
	}
	c.active = nil
}

func Import(ctx context.Context, age agecmd.Tool, destination *store.Store, bundlePath string) (result ImportResult, resultErr error) {
	if err := requireRegularFile(bundlePath); err != nil {
		return result, fmt.Errorf("inspect encrypted bundle: %w", err)
	}
	gitEnabled, err := destination.RequireCleanGit()
	if err != nil {
		return result, err
	}

	transactionID, err := newTransactionID()
	if err != nil {
		return result, err
	}
	result.TransactionID = transactionID
	transaction, err := destination.NewTransaction(transactionID)
	if err != nil {
		return result, err
	}
	keepTransaction := false
	transactionRemoved := false
	defer func() {
		if !keepTransaction && !transactionRemoved {
			resultErr = errors.Join(resultErr, transaction.Remove())
		}
	}()

	decrypted, err := age.StartDecrypt(ctx, destination.IdentitiesPath, bundlePath)
	if err != nil {
		return result, err
	}
	consumer := &stagingConsumer{ctx: ctx, age: age, store: destination, transaction: transaction}
	stats, decodeErr := protocol.Decode(decrypted, consumer)
	if decodeErr != nil {
		consumer.Abort()
		_ = decrypted.Abort()
		return result, fmt.Errorf("decode encrypted bundle: %w", decodeErr)
	}
	if err := decrypted.Close(); err != nil {
		consumer.Abort()
		return result, err
	}
	result.BundleEntries = stats.Entries
	result.Skipped = consumer.skipped

	lock, err := destination.AcquireLock("import")
	if err != nil {
		return result, err
	}
	defer func() {
		releaseErr := lock.Release()
		if releaseErr == nil {
			return
		}
		if result.Imported == 0 {
			resultErr = errors.Join(resultErr, releaseErr)
			return
		}
		result.Partial = true
		var applied *AppliedError
		if errors.As(resultErr, &applied) {
			applied.Result = result
			applied.Err = errors.Join(applied.Err, releaseErr)
			resultErr = applied
			return
		}
		resultErr = &AppliedError{Result: result, Err: errors.Join(resultErr, releaseErr)}
	}()

	if gitEnabledNow, err := destination.RequireCleanGit(); err != nil {
		return result, err
	} else if gitEnabledNow != gitEnabled {
		return result, errors.New("password repository Git state changed during import")
	}
	if err := verifyStore(ctx, age, destination); err != nil {
		return result, err
	}
	beforeDigests, err := destination.CiphertextDigests()
	if err != nil {
		return result, err
	}

	var candidates []stagedEntry
	for _, entry := range consumer.staged {
		exists, err := destination.Exists(entry.name)
		if err != nil {
			return result, err
		}
		if exists {
			result.Skipped++
			continue
		}
		candidates = append(candidates, entry)
	}
	if len(candidates) == 0 {
		if err := transaction.Remove(); err != nil {
			return result, err
		}
		transactionRemoved = true
		return result, nil
	}
	sort.Slice(candidates, func(left, right int) bool {
		return candidates[left].name < candidates[right].name
	})

	result.BackupBefore, err = destination.Snapshot(transactionID, "before")
	if err != nil {
		return result, err
	}
	journal, err := json.MarshalIndent(struct {
		Version        int      `json:"version"`
		TransactionID  string   `json:"transaction_id"`
		StartedAt      string   `json:"started_at"`
		CandidateNames []string `json:"candidate_names"`
	}{
		Version:        1,
		TransactionID:  transactionID,
		StartedAt:      time.Now().UTC().Format(time.RFC3339),
		CandidateNames: entryNames(candidates),
	}, "", "  ")
	if err != nil {
		return result, fmt.Errorf("encode transaction journal: %w", err)
	}
	if _, err := transaction.WriteJournal(append(journal, '\n')); err != nil {
		return result, err
	}

	var (
		added    []stagedEntry
		applyErr error
	)
	for _, entry := range candidates {
		published, err := transaction.Publish(entry.name)
		if published {
			added = append(added, entry)
		}
		if err != nil {
			applyErr = errors.Join(applyErr, err)
			break
		}
		if !published {
			result.Skipped++
		}
	}
	result.Imported = len(added)

	applyErr = errors.Join(applyErr, verifyImport(ctx, age, destination, beforeDigests, added))
	if gitEnabled && len(added) > 0 {
		if err := destination.Commit(entryNames(added), fmt.Sprintf("import %d password entries", len(added))); err != nil {
			applyErr = errors.Join(applyErr, err)
		} else {
			result.GitCommitted = true
		}
	}
	if len(added) > 0 {
		result.BackupAfter, err = destination.Snapshot(transactionID, "after")
		applyErr = errors.Join(applyErr, err)
	}

	result.Partial = applyErr != nil
	receipt, receiptErr := json.MarshalIndent(struct {
		Version   int          `json:"version"`
		Completed string       `json:"completed_at"`
		Result    ImportResult `json:"result"`
	}{Version: 1, Completed: time.Now().UTC().Format(time.RFC3339), Result: result}, "", "  ")
	if receiptErr == nil {
		result.Receipt, receiptErr = destination.WriteReceipt(transactionID, append(receipt, '\n'))
	}
	applyErr = errors.Join(applyErr, receiptErr)

	if applyErr != nil {
		result.Partial = true
		keepTransaction = len(added) > 0
		if len(added) > 0 {
			return result, &AppliedError{Result: result, Err: applyErr}
		}
		return result, applyErr
	}
	if err := transaction.Remove(); err != nil {
		keepTransaction = true
		result.Partial = true
		return result, &AppliedError{Result: result, Err: err}
	}
	transactionRemoved = true
	return result, nil
}

func verifyStore(ctx context.Context, age agecmd.Tool, target *store.Store) error {
	names, err := target.List()
	if err != nil {
		return err
	}
	for _, name := range names {
		entryPath, err := target.EntryPath(name)
		if err != nil {
			return err
		}
		if _, _, err := plaintextDigest(ctx, age, target.IdentitiesPath, entryPath); err != nil {
			return fmt.Errorf("verify existing entry %q: %w", name, err)
		}
	}
	return nil
}

func verifyImport(ctx context.Context, age agecmd.Tool, target *store.Store, before map[string][sha256.Size]byte, added []stagedEntry) error {
	after, err := target.CiphertextDigests()
	if err != nil {
		return err
	}
	allowed := make(map[string]struct{}, len(before)+len(added))
	for name, digest := range before {
		allowed[name] = struct{}{}
		if actual, ok := after[name]; !ok || actual != digest {
			return fmt.Errorf("pre-existing entry %q changed during import", name)
		}
	}
	for _, entry := range added {
		allowed[entry.name] = struct{}{}
		entryPath, err := target.EntryPath(entry.name)
		if err != nil {
			return err
		}
		size, digest, err := plaintextDigest(ctx, age, target.IdentitiesPath, entryPath)
		if err != nil {
			return fmt.Errorf("verify imported entry %q: %w", entry.name, err)
		}
		if size != entry.size || digest != entry.digest {
			return fmt.Errorf("imported entry %q plaintext mismatch", entry.name)
		}
	}
	for name := range after {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("unexpected entry %q appeared during import", name)
		}
	}
	return nil
}

func plaintextDigest(ctx context.Context, age agecmd.Tool, identitiesPath, inputPath string) (uint64, [sha256.Size]byte, error) {
	reader, err := age.StartDecrypt(ctx, identitiesPath, inputPath)
	if err != nil {
		return 0, [sha256.Size]byte{}, err
	}
	digest := sha256.New()
	size, copyErr := io.Copy(digest, reader)
	closeErr := reader.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return 0, [sha256.Size]byte{}, err
	}
	var sum [sha256.Size]byte
	copy(sum[:], digest.Sum(nil))
	return uint64(size), sum, nil
}

func entryNames(entries []stagedEntry) []string {
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.name
	}
	return names
}

func newTransactionID() (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate transaction identifier: %w", err)
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}
