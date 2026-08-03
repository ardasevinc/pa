package peerregistry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/ardasevinc/pa/internal/remote"
	"github.com/ardasevinc/pa/internal/store"
)

const (
	Version       = 1
	maxRecordSize = 64 * 1024
)

var (
	ErrNotFound = errors.New("peer does not exist")
	ErrExists   = errors.New("peer already exists")
	ErrChanged  = errors.New("peer changed concurrently")
)

type Record struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
}

type AppliedError struct {
	Operation string
	Name      string
	Err       error
}

func (e *AppliedError) Error() string {
	return fmt.Sprintf("peer %s was applied but finalization failed for %q: %v", e.Operation, e.Name, e.Err)
}

func (e *AppliedError) Unwrap() error { return e.Err }

type Registry struct {
	store *store.Store
	root  *os.Root
}

func Open(opened *store.Store) (*Registry, error) {
	root, err := opened.OpenRoot(".")
	if err != nil {
		return nil, fmt.Errorf("open peer registry root: %w", err)
	}
	return &Registry{store: opened, root: root}, nil
}

func (r *Registry) Close() error { return r.root.Close() }

func ValidateName(name string) error {
	if len(name) == 0 || len(name) > 64 {
		return fmt.Errorf("invalid peer name %q", name)
	}
	if !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= '0' && name[0] <= '9')) {
		return fmt.Errorf("invalid peer name %q", name)
	}
	for _, character := range name {
		if !((character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-') {
			return fmt.Errorf("invalid peer name %q", name)
		}
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid peer name %q", name)
	}
	for _, reserved := range []string{"add", "list", "probe", "remove", "replace", "show"} {
		if name == reserved {
			return fmt.Errorf("peer name %q is reserved", name)
		}
	}
	return nil
}

func ValidateFingerprint(fingerprint string) error {
	if len(fingerprint) != len("sha256:")+64 || !strings.HasPrefix(fingerprint, "sha256:") {
		return errors.New("fingerprint must be canonical sha256 followed by 64 lowercase hexadecimal digits")
	}
	for _, character := range strings.TrimPrefix(fingerprint, "sha256:") {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return errors.New("fingerprint must be canonical sha256 followed by 64 lowercase hexadecimal digits")
		}
	}
	return nil
}

func ValidateRecord(record Record) error {
	if record.Version != Version {
		return fmt.Errorf("unsupported peer record version %d", record.Version)
	}
	if err := ValidateName(record.Name); err != nil {
		return err
	}
	if err := remote.ValidateHost(record.Host); err != nil {
		return fmt.Errorf("invalid peer host: %w", err)
	}
	if err := ValidateFingerprint(record.Fingerprint); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode peer record: %w", err)
	}
	if len(data)+1 > maxRecordSize {
		return errors.New("peer record is too large")
	}
	return nil
}

func (r *Registry) List() ([]Record, error) {
	present, err := r.requirePeersDirectory(false)
	if err != nil || !present {
		return []Record{}, err
	}
	directory, err := r.root.Open("peers")
	if err != nil {
		return nil, fmt.Errorf("open peer registry: %w", err)
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, fmt.Errorf("read peer registry: %w", err)
	}

	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if isTemporaryName(name) && entry.Type().IsRegular() {
			continue
		}
		if entry.Type()&fs.ModeSymlink != 0 || entry.IsDir() || !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("unexpected peer registry entry %q", name)
		}
		alias := strings.TrimSuffix(name, ".json")
		record, err := r.read(alias)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(left, right int) bool { return records[left].Name < records[right].Name })
	return records, nil
}

func (r *Registry) Get(name string) (Record, error) {
	if err := ValidateName(name); err != nil {
		return Record{}, err
	}
	return r.read(name)
}

func (r *Registry) Add(record Record) (returnErr error) {
	if err := ValidateRecord(record); err != nil {
		return err
	}
	lock, err := r.store.AcquireLock("peer-add")
	if err != nil {
		return err
	}
	applied := false
	defer func() { returnErr = finishMutation(returnErr, lock.Release(), applied, "add", record.Name) }()

	if _, err := r.Get(record.Name); err == nil {
		return fmt.Errorf("%w: %s", ErrExists, record.Name)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	if _, err := r.requirePeersDirectory(true); err != nil {
		return err
	}
	temporary, err := r.writeTemporary(record)
	if err != nil {
		return err
	}
	defer r.root.Remove(temporary)
	if err := r.root.Link(temporary, recordPath(record.Name)); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, record.Name)
		}
		return fmt.Errorf("publish peer: %w", err)
	}
	applied = true
	if err := r.syncDirectory("peers"); err != nil {
		return &AppliedError{Operation: "add", Name: record.Name, Err: err}
	}
	if err := r.root.Remove(temporary); err != nil {
		return &AppliedError{Operation: "add", Name: record.Name, Err: fmt.Errorf("remove staged peer: %w", err)}
	}
	temporary = ""
	if err := r.syncDirectory("peers"); err != nil {
		return &AppliedError{Operation: "add", Name: record.Name, Err: err}
	}
	return nil
}

func (r *Registry) Replace(expected, replacement Record) (returnErr error) {
	if err := ValidateRecord(expected); err != nil {
		return err
	}
	if err := ValidateRecord(replacement); err != nil {
		return err
	}
	if expected.Name != replacement.Name {
		return errors.New("replacement peer name differs")
	}
	lock, err := r.store.AcquireLock("peer-replace")
	if err != nil {
		return err
	}
	applied := false
	defer func() { returnErr = finishMutation(returnErr, lock.Release(), applied, "replace", replacement.Name) }()

	current, err := r.Get(expected.Name)
	if err != nil {
		return err
	}
	if current != expected {
		return fmt.Errorf("%w: %s", ErrChanged, expected.Name)
	}
	temporary, err := r.writeTemporary(replacement)
	if err != nil {
		return err
	}
	defer r.root.Remove(temporary)
	if err := r.root.Rename(temporary, recordPath(replacement.Name)); err != nil {
		return fmt.Errorf("replace peer: %w", err)
	}
	applied = true
	if err := r.syncDirectory("peers"); err != nil {
		return &AppliedError{Operation: "replace", Name: replacement.Name, Err: err}
	}
	return nil
}

func (r *Registry) Remove(expected Record) (returnErr error) {
	if err := ValidateRecord(expected); err != nil {
		return err
	}
	lock, err := r.store.AcquireLock("peer-remove")
	if err != nil {
		return err
	}
	applied := false
	defer func() { returnErr = finishMutation(returnErr, lock.Release(), applied, "remove", expected.Name) }()

	current, err := r.Get(expected.Name)
	if err != nil {
		return err
	}
	if current != expected {
		return fmt.Errorf("%w: %s", ErrChanged, expected.Name)
	}
	if err := r.root.Remove(recordPath(expected.Name)); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}
	applied = true
	if err := r.syncDirectory("peers"); err != nil {
		return &AppliedError{Operation: "remove", Name: expected.Name, Err: err}
	}
	return nil
}

func (r *Registry) read(name string) (Record, error) {
	if err := ValidateName(name); err != nil {
		return Record{}, err
	}
	present, err := r.requirePeersDirectory(false)
	if err != nil {
		return Record{}, err
	}
	if !present {
		return Record{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	namePath := recordPath(name)
	info, err := r.root.Lstat(namePath)
	if errors.Is(err, fs.ErrNotExist) {
		return Record{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return Record{}, fmt.Errorf("inspect peer %q: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return Record{}, fmt.Errorf("peer %q is not a regular file", name)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Record{}, fmt.Errorf("peer %q is accessible by other users", name)
	}
	if info.Size() < 0 || info.Size() > maxRecordSize {
		return Record{}, fmt.Errorf("peer %q record is too large", name)
	}
	file, err := r.root.Open(namePath)
	if err != nil {
		return Record{}, fmt.Errorf("open peer %q: %w", name, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxRecordSize+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return Record{}, fmt.Errorf("read peer %q: %w", name, err)
	}
	if len(data) > maxRecordSize {
		return Record{}, fmt.Errorf("peer %q record is too large", name)
	}
	record, err := decodeRecord(data)
	if err != nil {
		return Record{}, fmt.Errorf("decode peer %q: %w", name, err)
	}
	if record.Name != name {
		return Record{}, fmt.Errorf("peer record name %q differs from filename %q", record.Name, name)
	}
	return record, nil
}

func (r *Registry) requirePeersDirectory(create bool) (bool, error) {
	info, err := r.root.Lstat("peers")
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := r.root.Mkdir("peers", 0o700); err != nil {
			return false, fmt.Errorf("create peer registry: %w", err)
		}
		if err := r.syncDirectory("."); err != nil {
			return true, err
		}
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect peer registry: %w", err)
	}
	if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return false, errors.New("pa peers path is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return false, errors.New("pa peers directory is accessible by other users")
	}
	return true, nil
}

func (r *Registry) writeTemporary(record Record) (string, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	name := path.Join("peers", ".pa-peer-"+hex.EncodeToString(random)+".tmp")
	file, err := r.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create staged peer: %w", err)
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = r.root.Remove(name)
		return "", fmt.Errorf("write staged peer: %w", err)
	}
	return name, nil
}

func (r *Registry) syncDirectory(name string) error {
	directory, err := r.root.Open(name)
	if err != nil {
		return fmt.Errorf("open peer directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return fmt.Errorf("sync peer directory: %w", err)
	}
	return nil
}

func decodeRecord(data []byte) (Record, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return Record{}, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return Record{}, errors.New("peer record must be a JSON object")
	}
	var record Record
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return Record{}, err
		}
		field, ok := token.(string)
		if !ok {
			return Record{}, errors.New("peer record field must be a string")
		}
		if _, exists := seen[field]; exists {
			return Record{}, fmt.Errorf("duplicate peer record field %q", field)
		}
		seen[field] = struct{}{}
		switch field {
		case "version":
			err = decoder.Decode(&record.Version)
		case "name":
			err = decoder.Decode(&record.Name)
		case "host":
			err = decoder.Decode(&record.Host)
		case "fingerprint":
			err = decoder.Decode(&record.Fingerprint)
		default:
			return Record{}, fmt.Errorf("unknown peer record field %q", field)
		}
		if err != nil {
			return Record{}, fmt.Errorf("decode peer record field %q: %w", field, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return Record{}, err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return Record{}, err
		}
		return Record{}, fmt.Errorf("trailing peer record data %v", token)
	}
	if err := ValidateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func recordPath(name string) string { return path.Join("peers", name+".json") }

func isTemporaryName(name string) bool {
	return strings.HasPrefix(name, ".pa-peer-") && strings.HasSuffix(name, ".tmp")
}

func finishMutation(operationErr, releaseErr error, applied bool, operation, name string) error {
	if releaseErr == nil {
		return operationErr
	}
	if applied {
		return errors.Join(operationErr, &AppliedError{Operation: operation, Name: name, Err: releaseErr})
	}
	return errors.Join(operationErr, releaseErr)
}
