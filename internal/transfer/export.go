package transfer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/protocol"
	"github.com/ardasevinc/pa/internal/store"
)

type ExportResult struct {
	Entries uint32 `json:"entries"`
	Bytes   uint64 `json:"bytes"`
	Output  string `json:"output"`
}

func Export(ctx context.Context, age agecmd.Tool, source *store.Store, recipientsPath, outputPath string) (result ExportResult, resultErr error) {
	lock, err := source.AcquireLock("export")
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, lock.Release())
	}()
	return exportLocked(ctx, age, source, recipientsPath, outputPath)
}

// ExportLocked exports while the caller holds the source store lock. This is
// used when a higher-level operation must keep another invariant stable through
// delivery of the resulting encrypted bundle.
func ExportLocked(ctx context.Context, age agecmd.Tool, source *store.Store, recipientsPath, outputPath string) (result ExportResult, resultErr error) {
	return exportLocked(ctx, age, source, recipientsPath, outputPath)
}

func exportLocked(ctx context.Context, age agecmd.Tool, source *store.Store, recipientsPath, outputPath string) (result ExportResult, resultErr error) {
	outputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return result, fmt.Errorf("resolve export path: %w", err)
	}
	if inside(outputPath, source.PasswordsDir) {
		return result, errors.New("export output cannot be inside the password store")
	}
	if err := requireRegularFile(recipientsPath); err != nil {
		return result, fmt.Errorf("inspect export recipients: %w", err)
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return result, fmt.Errorf("export output already exists: %s", outputPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return result, fmt.Errorf("inspect export output: %w", err)
	}

	names, err := source.List()
	if err != nil {
		return result, err
	}

	temporary, err := os.CreateTemp(filepath.Dir(outputPath), ".pa-export-*.age")
	if err != nil {
		return result, fmt.Errorf("create encrypted export staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	if err := errors.Join(temporary.Chmod(0o600), temporary.Close()); err != nil {
		_ = os.Remove(temporaryPath)
		return result, fmt.Errorf("prepare encrypted export staging file: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(temporaryPath)
		}
	}()

	encrypted, err := age.StartEncrypt(ctx, recipientsPath, temporaryPath)
	if err != nil {
		return result, err
	}
	encryptionOpen := true
	defer func() {
		if encryptionOpen {
			_ = encrypted.Abort()
		}
	}()

	encoder, err := protocol.NewEncoder(encrypted)
	if err != nil {
		return result, err
	}
	for _, name := range names {
		entryPath, err := source.EntryPath(name)
		if err != nil {
			return result, err
		}
		decrypted, err := age.StartDecrypt(ctx, source.IdentitiesPath, entryPath)
		if err != nil {
			return result, fmt.Errorf("decrypt entry %q: %w", name, err)
		}
		if err := encoder.Add(name, decrypted); err != nil {
			_ = decrypted.Abort()
			return result, fmt.Errorf("encode entry %q: %w", name, err)
		}
		if err := decrypted.Close(); err != nil {
			return result, fmt.Errorf("decrypt entry %q: %w", name, err)
		}
	}

	stats, err := encoder.Close()
	if err != nil {
		return result, fmt.Errorf("finish transfer bundle: %w", err)
	}
	if err := encrypted.Close(); err != nil {
		encryptionOpen = false
		return result, err
	}
	encryptionOpen = false

	if err := syncFile(temporaryPath); err != nil {
		return result, err
	}
	if err := os.Link(temporaryPath, outputPath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return result, fmt.Errorf("export output appeared during export: %s", outputPath)
		}
		return result, fmt.Errorf("publish encrypted export: %w", err)
	}
	if err := syncDirectory(filepath.Dir(outputPath)); err != nil {
		return result, err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return result, fmt.Errorf("remove encrypted export staging file: %w", err)
	}
	complete = true

	return ExportResult{Entries: stats.Entries, Bytes: stats.Bytes, Output: outputPath}, nil
}

func inside(candidate, directory string) bool {
	relative, err := filepath.Rel(directory, candidate)
	return err == nil && relative != ".." && relative != "." && !filepath.IsAbs(relative) &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func requireRegularFile(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", name)
	}
	return nil
}

func syncFile(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("open file for sync: %w", err)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return fmt.Errorf("sync file: %w", err)
	}
	return nil
}

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
