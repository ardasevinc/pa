package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/protocol"
	"github.com/ardasevinc/pa/internal/store"
)

type Backup struct {
	TransactionID string `json:"transaction_id"`
	Before        bool   `json:"before"`
	After         bool   `json:"after"`
	Receipt       bool   `json:"receipt"`
}

type RestoreResult struct {
	TransactionID string `json:"transaction_id"`
	SourceID      string `json:"source_id"`
	SourcePhase   string `json:"source_phase"`
	Restored      int    `json:"restored"`
	Removed       int    `json:"removed"`
	BackupBefore  string `json:"backup_before,omitempty"`
	BackupAfter   string `json:"backup_after,omitempty"`
	Receipt       string `json:"receipt,omitempty"`
	GitCommitted  bool   `json:"git_committed"`
	Partial       bool   `json:"partial"`
}

type AppliedError struct {
	Result RestoreResult
	Err    error
}

func (e *AppliedError) Error() string {
	return fmt.Sprintf("password recovery changes were applied but finalization failed: %v", e.Err)
}

func (e *AppliedError) Unwrap() error { return e.Err }

type RestoreOptions struct {
	AllowDirty bool
}

type treeEntry struct {
	path   string
	digest [sha256.Size]byte
}

func List(storeDirectory string) ([]Backup, error) {
	backupsDirectory := filepath.Join(storeDirectory, "backups")
	entries, err := os.ReadDir(backupsDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	backups := make([]Backup, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || validateID(entry.Name()) != nil {
			continue
		}
		directory := filepath.Join(backupsDirectory, entry.Name())
		backups = append(backups, Backup{
			TransactionID: entry.Name(),
			Before:        isRealDirectory(filepath.Join(directory, "before", "passwords")),
			After:         isRealDirectory(filepath.Join(directory, "after", "passwords")),
			Receipt:       isRegular(filepath.Join(directory, "receipt.json")),
		})
	}
	sort.Slice(backups, func(left, right int) bool {
		return backups[left].TransactionID > backups[right].TransactionID
	})
	return backups, nil
}

func Restore(ctx context.Context, age agecmd.Tool, destination *store.Store, sourceID, phase string) (result RestoreResult, resultErr error) {
	return RestoreWithOptions(ctx, age, destination, sourceID, phase, RestoreOptions{})
}

func RestoreWithOptions(ctx context.Context, age agecmd.Tool, destination *store.Store, sourceID, phase string, options RestoreOptions) (result RestoreResult, resultErr error) {
	if err := validateID(sourceID); err != nil {
		return result, err
	}
	if phase != "before" && phase != "after" {
		return result, fmt.Errorf("invalid backup phase %q", phase)
	}
	result.SourceID = sourceID
	result.SourcePhase = phase
	sourceDirectory := filepath.Join(destination.Dir, "backups", sourceID, phase, "passwords")
	sourceEntries, err := inspectTree(ctx, age, destination.IdentitiesPath, sourceDirectory)
	if err != nil {
		return result, fmt.Errorf("inspect recovery source: %w", err)
	}
	gitEnabled, dirty, err := gitState(destination)
	if err != nil || (dirty && !options.AllowDirty) {
		if dirty && err == nil {
			err = store.ErrDirtyGit
		}
		return result, err
	}
	if _, err := inspectTree(ctx, age, destination.IdentitiesPath, destination.PasswordsDir); err != nil {
		return result, fmt.Errorf("verify current store: %w", err)
	}

	transactionID, err := newTransactionID()
	if err != nil {
		return result, err
	}
	result.TransactionID = transactionID
	lock, err := destination.AcquireLock("restore")
	if err != nil {
		return result, err
	}
	defer func() {
		releaseErr := lock.Release()
		if releaseErr == nil {
			return
		}
		if result.Restored+result.Removed == 0 {
			resultErr = errors.Join(resultErr, releaseErr)
			return
		}
		result.Partial = true
		resultErr = &AppliedError{Result: result, Err: errors.Join(resultErr, releaseErr)}
	}()

	if enabledNow, dirtyNow, err := gitState(destination); err != nil {
		return result, err
	} else if dirtyNow && !options.AllowDirty {
		return result, store.ErrDirtyGit
	} else if enabledNow != gitEnabled {
		return result, errors.New("password repository Git state changed during restore")
	}
	currentEntries, err := inspectTree(ctx, age, destination.IdentitiesPath, destination.PasswordsDir)
	if err != nil {
		return result, err
	}
	currentNames := mapKeys(currentEntries)
	restoreNames := make([]string, 0, len(sourceEntries))
	for _, name := range mapKeys(sourceEntries) {
		current, exists := currentEntries[name]
		if !exists || current.digest != sourceEntries[name].digest {
			restoreNames = append(restoreNames, name)
		}
	}
	removeNames := make([]string, 0, len(currentEntries))
	for _, name := range currentNames {
		if _, desired := sourceEntries[name]; !desired {
			removeNames = append(removeNames, name)
		}
	}
	if len(restoreNames) == 0 && len(removeNames) == 0 {
		return result, nil
	}
	result.BackupBefore, err = destination.Snapshot(transactionID, "before")
	if err != nil {
		return result, err
	}
	transaction, err := destination.NewTransaction(transactionID)
	if err != nil {
		return result, err
	}
	transactionFinalized := false
	defer func() {
		if !transactionFinalized && result.Restored+result.Removed == 0 {
			resultErr = errors.Join(resultErr, transaction.Remove())
		}
	}()
	journal, err := json.MarshalIndent(struct {
		Version       int      `json:"version"`
		TransactionID string   `json:"transaction_id"`
		SourceID      string   `json:"source_id"`
		SourcePhase   string   `json:"source_phase"`
		StartedAt     string   `json:"started_at"`
		DesiredNames  []string `json:"desired_names"`
	}{1, transactionID, sourceID, phase, time.Now().UTC().Format(time.RFC3339), mapKeys(sourceEntries)}, "", "  ")
	if err != nil {
		return result, err
	}
	if _, err := transaction.WriteJournal(append(journal, '\n')); err != nil {
		return result, err
	}

	for _, name := range restoreNames {
		_, stagedPath, err := transaction.StagePath(name)
		if err != nil {
			return result, err
		}
		if err := copyNewFile(sourceEntries[name].path, stagedPath); err != nil {
			return result, fmt.Errorf("stage recovery entry %q: %w", name, err)
		}
	}

	changed := make([]string, 0, len(sourceEntries)+len(currentNames))
	for _, name := range restoreNames {
		applied, err := transaction.Replace(name)
		if applied {
			result.Restored++
			changed = append(changed, name)
		}
		if err != nil {
			return appliedResult(result, err)
		}
	}
	for _, name := range removeNames {
		applied, err := transaction.Displace(name)
		if applied {
			result.Removed++
			changed = append(changed, name)
		}
		if err != nil {
			return appliedResult(result, err)
		}
	}

	actualEntries, err := inspectTree(ctx, age, destination.IdentitiesPath, destination.PasswordsDir)
	if err != nil {
		return appliedResult(result, err)
	}
	if !sameEntries(sourceEntries, actualEntries) {
		return appliedResult(result, errors.New("restored ciphertext does not exactly match backup"))
	}
	if gitEnabled && len(changed) > 0 {
		sort.Strings(changed)
		changed = compact(changed)
		if err := destination.Commit(changed, fmt.Sprintf("restore backup %s %s", sourceID, phase)); err != nil {
			return appliedResult(result, err)
		}
		result.GitCommitted = true
	}
	result.BackupAfter, err = destination.Snapshot(transactionID, "after")
	if err != nil {
		return appliedResult(result, err)
	}
	receipt, err := json.MarshalIndent(struct {
		Version     int           `json:"version"`
		CompletedAt string        `json:"completed_at"`
		Result      RestoreResult `json:"result"`
	}{1, time.Now().UTC().Format(time.RFC3339), result}, "", "  ")
	if err == nil {
		result.Receipt, err = destination.WriteReceipt(transactionID, append(receipt, '\n'))
	}
	if err != nil {
		return appliedResult(result, err)
	}
	if err := transaction.Remove(); err != nil {
		return appliedResult(result, err)
	}
	transactionFinalized = true
	return result, nil
}

func gitState(target *store.Store) (enabled, dirty bool, err error) {
	enabled, err = target.RequireCleanGit()
	if errors.Is(err, store.ErrDirtyGit) {
		return enabled, true, nil
	}
	return enabled, false, err
}

func inspectTree(ctx context.Context, age agecmd.Tool, identitiesPath, directory string) (map[string]treeEntry, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("password tree is not a real directory")
	}
	entries := make(map[string]treeEntry)
	err = filepath.WalkDir(directory, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == directory {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link in password tree: %s", current)
		}
		relative, err := filepath.Rel(directory, current)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relative == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file in password tree: %s", current)
		}
		if !strings.HasSuffix(relative, ".age") {
			return nil
		}
		name := filepath.ToSlash(strings.TrimSuffix(relative, ".age"))
		if err := protocol.ValidateName(name); err != nil {
			return err
		}
		reader, err := age.StartDecrypt(ctx, identitiesPath, current)
		if err != nil {
			return err
		}
		_, readErr := io.Copy(io.Discard, reader)
		if err := errors.Join(readErr, reader.Close()); err != nil {
			return fmt.Errorf("decrypt %q: %w", name, err)
		}
		ciphertext, err := os.Open(current)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, hashErr := io.Copy(hash, ciphertext)
		closeErr := ciphertext.Close()
		if err := errors.Join(hashErr, closeErr); err != nil {
			return err
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		entries[name] = treeEntry{path: current, digest: digest}
		return nil
	})
	return entries, err
}

func copyNewFile(sourcePath, destinationPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = source.Close()
		return err
	}
	_, copyErr := io.Copy(destination, source)
	syncErr := destination.Sync()
	return errors.Join(copyErr, syncErr, source.Close(), destination.Close())
}

func appliedResult(result RestoreResult, err error) (RestoreResult, error) {
	if result.Restored+result.Removed == 0 {
		return result, err
	}
	result.Partial = true
	return result, &AppliedError{Result: result, Err: err}
}

func mapKeys(values map[string]treeEntry) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sameEntries(left, right map[string]treeEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for name, entry := range left {
		if actual, ok := right[name]; !ok || actual.digest != entry.digest {
			return false
		}
	}
	return true
}

func compact(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func validateID(value string) error {
	if value == "" || len(value) > 128 {
		return errors.New("invalid backup transaction identifier")
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return errors.New("invalid backup transaction identifier")
		}
	}
	return nil
}

func newTransactionID() (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "restore-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func isRealDirectory(name string) bool {
	info, err := os.Lstat(name)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func isRegular(name string) bool {
	info, err := os.Lstat(name)
	return err == nil && info.Mode().IsRegular()
}
