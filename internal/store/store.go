package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ardasevinc/pa/internal/protocol"
)

var (
	ErrLocked    = errors.New("pa store is locked")
	ErrDirtyGit  = errors.New("pa password repository is dirty")
	ErrEntryGone = errors.New("pa entry does not exist")
)

type Store struct {
	Dir            string
	PasswordsDir   string
	IdentitiesPath string
	RecipientsPath string

	root          *os.Root
	passwordsRoot *os.Root
}

func Open(directory string) (*Store, error) {
	if !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("store path must be absolute: %q", directory)
	}

	passwordsDirectory := filepath.Join(directory, "passwords")
	if err := requireDirectory(passwordsDirectory); err != nil {
		return nil, err
	}
	identitiesPath := filepath.Join(directory, "identities")
	if err := requireRegularFile(identitiesPath); err != nil {
		return nil, err
	}
	recipientsPath := filepath.Join(directory, "recipients")
	if err := requireRegularFile(recipientsPath); err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open store root: %w", err)
	}
	passwordsRoot, err := os.OpenRoot(passwordsDirectory)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open password root: %w", err)
	}

	return &Store{
		Dir:            directory,
		PasswordsDir:   passwordsDirectory,
		IdentitiesPath: identitiesPath,
		RecipientsPath: recipientsPath,
		root:           root,
		passwordsRoot:  passwordsRoot,
	}, nil
}

func (s *Store) Close() error {
	return errors.Join(s.passwordsRoot.Close(), s.root.Close())
}

func (s *Store) List() ([]string, error) {
	var names []string
	err := fs.WalkDir(s.passwordsRoot.FS(), ".", func(currentPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if currentPath == "." {
			return nil
		}

		component := path.Base(currentPath)
		if entry.IsDir() && (component == ".git" || strings.HasPrefix(component, ".pa-")) {
			return fs.SkipDir
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link in password store: %s", currentPath)
		}
		if entry.IsDir() || !strings.HasSuffix(currentPath, ".age") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular password entry: %s", currentPath)
		}

		name := strings.TrimSuffix(currentPath, ".age")
		if err := protocol.ValidateName(name); err != nil {
			return fmt.Errorf("invalid stored entry %q: %w", name, err)
		}
		names = append(names, name)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventory password store: %w", err)
	}

	sort.Strings(names)
	return names, nil
}

func (s *Store) EntryPath(name string) (string, error) {
	if err := protocol.ValidateName(name); err != nil {
		return "", err
	}
	return filepath.Join(s.PasswordsDir, filepath.FromSlash(name)+".age"), nil
}

func (s *Store) Exists(name string) (bool, error) {
	entryPath, err := entryRelativePath(name)
	if err != nil {
		return false, err
	}
	info, err := s.passwordsRoot.Lstat(entryPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect entry %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("entry %q is not a regular file", name)
	}
	return true, nil
}

func (s *Store) RequireCleanGit() (bool, error) {
	if _, err := s.passwordsRoot.Stat(".git"); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect password repository: %w", err)
	}

	command := exec.Command("git", "-C", s.PasswordsDir, "status", "--porcelain=v1", "--untracked-files=all")
	output, err := command.Output()
	if err != nil {
		return true, fmt.Errorf("inspect password repository: %w", err)
	}
	if len(output) != 0 {
		return true, ErrDirtyGit
	}
	return true, nil
}

func (s *Store) CiphertextDigests() (map[string][sha256.Size]byte, error) {
	names, err := s.List()
	if err != nil {
		return nil, err
	}

	digests := make(map[string][sha256.Size]byte, len(names))
	for _, name := range names {
		entryPath, err := entryRelativePath(name)
		if err != nil {
			return nil, err
		}
		file, err := s.passwordsRoot.Open(entryPath)
		if err != nil {
			return nil, fmt.Errorf("open entry %q: %w", name, err)
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return nil, fmt.Errorf("hash entry %q: %w", name, err)
		}
		var sum [sha256.Size]byte
		copy(sum[:], digest.Sum(nil))
		digests[name] = sum
	}
	return digests, nil
}

func (s *Store) Snapshot(transactionID, phase string) (string, error) {
	if err := validateInternalID(transactionID); err != nil {
		return "", err
	}
	if phase != "before" && phase != "after" {
		return "", fmt.Errorf("invalid snapshot phase %q", phase)
	}

	destination := path.Join("backups", transactionID, phase, "passwords")
	if err := s.root.MkdirAll(destination, 0o700); err != nil {
		return "", fmt.Errorf("create snapshot directory: %w", err)
	}

	err := fs.WalkDir(s.passwordsRoot.FS(), ".", func(sourcePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if sourcePath == "." {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refuse symbolic link in snapshot: %s", sourcePath)
		}

		destinationPath := path.Join(destination, sourcePath)
		if entry.IsDir() {
			return s.root.MkdirAll(destinationPath, 0o700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refuse non-regular snapshot file: %s", sourcePath)
		}

		source, err := s.passwordsRoot.Open(sourcePath)
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		if mode == 0 {
			mode = 0o600
		}
		target, err := s.root.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			_ = source.Close()
			return err
		}
		_, copyErr := io.Copy(target, source)
		syncErr := target.Sync()
		closeErr := errors.Join(source.Close(), target.Close())
		return errors.Join(copyErr, syncErr, closeErr)
	})
	if err != nil {
		return "", fmt.Errorf("snapshot password store: %w", err)
	}

	if err := s.syncDirectory(path.Dir(destination)); err != nil {
		return "", err
	}
	return filepath.Join(s.Dir, filepath.FromSlash(destination)), nil
}

func (s *Store) NewTransaction(transactionID string) (*Transaction, error) {
	if err := validateInternalID(transactionID); err != nil {
		return nil, err
	}
	rootPath := path.Join("transactions", transactionID)
	if err := s.root.MkdirAll(path.Join(rootPath, "entries"), 0o700); err != nil {
		return nil, fmt.Errorf("create transaction: %w", err)
	}
	return &Transaction{store: s, id: transactionID, rootPath: rootPath}, nil
}

func (s *Store) Commit(names []string, message string) error {
	if len(names) == 0 {
		return nil
	}
	arguments := []string{"-C", s.PasswordsDir, "add", "--"}
	for _, name := range names {
		entryPath, err := entryRelativePath(name)
		if err != nil {
			return err
		}
		arguments = append(arguments, filepath.FromSlash(entryPath))
	}
	if output, err := exec.Command("git", arguments...).CombinedOutput(); err != nil {
		return fmt.Errorf("git add imported entries: %w: %s", err, strings.TrimSpace(string(output)))
	}

	arguments = []string{"-C", s.PasswordsDir, "commit", "-m", message, "--"}
	for _, name := range names {
		entryPath, _ := entryRelativePath(name)
		arguments = append(arguments, filepath.FromSlash(entryPath))
	}
	if output, err := exec.Command("git", arguments...).CombinedOutput(); err != nil {
		return fmt.Errorf("git commit imported entries: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s *Store) syncDirectory(relativePath string) error {
	directory, err := s.root.Open(relativePath)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

type Lock struct {
	store *Store
	token string
	held  bool
}

func (s *Store) AcquireLock(operation string) (*Lock, error) {
	if err := s.root.Mkdir("lock", 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			info, _ := s.root.ReadFile("lock/info")
			return nil, fmt.Errorf("%w: %s", ErrLocked, strings.TrimSpace(string(info)))
		}
		return nil, fmt.Errorf("create store lock: %w", err)
	}

	token, err := randomID()
	if err != nil {
		_ = s.root.Remove("lock")
		return nil, err
	}
	lock := &Lock{store: s, token: token, held: true}

	if err := s.root.WriteFile("lock/owner", []byte(token+"\n"), 0o600); err != nil {
		_ = lock.Release()
		return nil, fmt.Errorf("write lock owner: %w", err)
	}
	info := fmt.Sprintf("pid=%d host=%s operation=%s started=%s\n", os.Getpid(), hostname(), operation, time.Now().UTC().Format(time.RFC3339))
	if err := s.root.WriteFile("lock/info", []byte(info), 0o600); err != nil {
		_ = lock.Release()
		return nil, fmt.Errorf("write lock information: %w", err)
	}
	return lock, nil
}

func (l *Lock) Release() error {
	if !l.held {
		return nil
	}
	owner, err := l.store.root.ReadFile("lock/owner")
	if err != nil {
		return fmt.Errorf("read lock owner: %w", err)
	}
	if strings.TrimSpace(string(owner)) != l.token {
		return errors.New("store lock ownership changed")
	}

	var releaseErrors []error
	for _, file := range []string{"lock/owner", "lock/info"} {
		if err := l.store.root.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			releaseErrors = append(releaseErrors, err)
		}
	}
	if err := l.store.root.Remove("lock"); err != nil {
		releaseErrors = append(releaseErrors, err)
	}
	if err := errors.Join(releaseErrors...); err != nil {
		return fmt.Errorf("release store lock: %w", err)
	}
	l.held = false
	return nil
}

type Transaction struct {
	store    *Store
	id       string
	rootPath string
}

func (t *Transaction) StagePath(name string) (relativePath, absolutePath string, err error) {
	entryPath, err := entryRelativePath(name)
	if err != nil {
		return "", "", err
	}
	relativePath = path.Join(t.rootPath, "entries", entryPath)
	if err := t.store.root.MkdirAll(path.Dir(relativePath), 0o700); err != nil {
		return "", "", fmt.Errorf("create staged entry directory: %w", err)
	}
	if _, err := t.store.root.Lstat(relativePath); err == nil {
		return "", "", fmt.Errorf("staged entry already exists: %s", name)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", "", err
	}
	return relativePath, filepath.Join(t.store.Dir, filepath.FromSlash(relativePath)), nil
}

func (t *Transaction) Publish(name string) (bool, error) {
	entryPath, err := entryRelativePath(name)
	if err != nil {
		return false, err
	}
	stagedPath := path.Join(t.rootPath, "entries", entryPath)
	finalPath := path.Join("passwords", entryPath)
	if err := t.store.root.MkdirAll(path.Dir(finalPath), 0o700); err != nil {
		return false, fmt.Errorf("create destination category: %w", err)
	}
	if err := t.store.root.Link(stagedPath, finalPath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("publish entry %q: %w", name, err)
	}
	if err := t.store.syncFile(finalPath); err != nil {
		return true, err
	}
	if err := t.store.syncDirectory(path.Dir(finalPath)); err != nil {
		return true, err
	}
	return true, nil
}

func (t *Transaction) Remove() error {
	if err := t.store.root.RemoveAll(t.rootPath); err != nil {
		return fmt.Errorf("remove transaction: %w", err)
	}
	return nil
}

func (s *Store) syncFile(relativePath string) error {
	file, err := s.root.Open(relativePath)
	if err != nil {
		return fmt.Errorf("open file for sync: %w", err)
	}
	err = file.Sync()
	closeErr := file.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return fmt.Errorf("sync file: %w", err)
	}
	return nil
}

func entryRelativePath(name string) (string, error) {
	if err := protocol.ValidateName(name); err != nil {
		return "", err
	}
	return name + ".age", nil
}

func requireDirectory(filePath string) error {
	info, err := os.Lstat(filePath)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", filePath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory: %s", filePath)
	}
	return nil
}

func requireRegularFile(filePath string) error {
	info, err := os.Lstat(filePath)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", filePath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", filePath)
	}
	return nil
}

func validateInternalID(value string) error {
	if value == "" || len(value) > 128 {
		return fmt.Errorf("invalid internal identifier %q", value)
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_') {
			return fmt.Errorf("invalid internal identifier %q", value)
		}
	}
	return nil
}

func randomID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate random identifier: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
