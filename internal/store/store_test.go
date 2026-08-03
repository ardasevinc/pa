package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "passwords"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "identities"), []byte("test identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "recipients"), []byte("test recipient\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func writeEntry(t *testing.T, store *Store, name string, value []byte) {
	t.Helper()
	entryPath, err := store.EntryPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(entryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entryPath, value, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestListAndCiphertextDigests(t *testing.T) {
	store := newTestStore(t)
	writeEntry(t, store, "z-last", []byte("z"))
	writeEntry(t, store, "nested/first", []byte("first"))
	if err := os.WriteFile(filepath.Join(store.PasswordsDir, ".gitattributes"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(store.PasswordsDir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.PasswordsDir, ".git", "secret.age"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}

	names, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"nested/first", "z-last"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("List() = %v, want %v", names, wantNames)
	}

	digests, err := store.CiphertextDigests()
	if err != nil {
		t.Fatal(err)
	}
	if digests["nested/first"] != sha256.Sum256([]byte("first")) {
		t.Error("CiphertextDigests() returned wrong digest")
	}
}

func TestListRejectsSymlinks(t *testing.T) {
	store := newTestStore(t)
	outside := filepath.Join(t.TempDir(), "outside.age")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store.PasswordsDir, "linked.age")); err != nil {
		t.Fatal(err)
	}

	if _, err := store.List(); err == nil {
		t.Fatal("List() accepted a symbolic link")
	}
	if _, err := store.Exists("linked"); err == nil {
		t.Fatal("Exists() accepted a symbolic link")
	}
}

func TestLockOwnership(t *testing.T) {
	store := newTestStore(t)
	first, err := store.AcquireLock("test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLock("second"); !errors.Is(err, ErrLocked) {
		t.Fatalf("second AcquireLock() error = %v, want ErrLocked", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("second Release() error = %v", err)
	}

	second, err := store.AcquireLock("after-release")
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionPublishesWithoutReplacement(t *testing.T) {
	store := newTestStore(t)
	first, err := store.NewTransaction("first")
	if err != nil {
		t.Fatal(err)
	}
	_, firstPath, err := first.StagePath("nested/entry")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstPath, []byte("first ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	published, err := first.Publish("nested/entry")
	if err != nil || !published {
		t.Fatalf("first Publish() = %v, %v, want true, nil", published, err)
	}
	if err := first.Remove(); err != nil {
		t.Fatal(err)
	}

	second, err := store.NewTransaction("second")
	if err != nil {
		t.Fatal(err)
	}
	_, secondPath, err := second.StagePath("nested/entry")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte("second ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	published, err = second.Publish("nested/entry")
	if err != nil || published {
		t.Fatalf("second Publish() = %v, %v, want false, nil", published, err)
	}

	entryPath, _ := store.EntryPath("nested/entry")
	actual, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, []byte("first ciphertext")) {
		t.Fatalf("destination was replaced: %q", actual)
	}
}

func TestSnapshotCopiesPasswordTree(t *testing.T) {
	store := newTestStore(t)
	writeEntry(t, store, "nested/entry", []byte("ciphertext"))
	if err := os.Mkdir(filepath.Join(store.PasswordsDir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.PasswordsDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.Snapshot("transaction", "before")
	if err != nil {
		t.Fatal(err)
	}
	for _, relativePath := range []string{"nested/entry.age", ".git/HEAD"} {
		source, err := os.ReadFile(filepath.Join(store.PasswordsDir, relativePath))
		if err != nil {
			t.Fatal(err)
		}
		copied, err := os.ReadFile(filepath.Join(snapshot, relativePath))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(source, copied) {
			t.Errorf("snapshot mismatch for %s", relativePath)
		}
	}
}

func TestWriteNewSyncedFilePreservesExistingFile(t *testing.T) {
	store := newTestStore(t)
	const name = "existing.json"
	if err := store.root.WriteFile(name, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeNewSyncedFile(store.root, name, []byte("replacement"), 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("writeNewSyncedFile() error = %v, want fs.ErrExist", err)
	}
	actual, err := store.root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, []byte("original")) {
		t.Fatalf("existing file changed: %q", actual)
	}
}

func TestRequireCleanGitAndCommit(t *testing.T) {
	store := newTestStore(t)
	runGit(t, store.PasswordsDir, "init", "-q")
	runGit(t, store.PasswordsDir, "config", "user.name", "pa test")
	runGit(t, store.PasswordsDir, "config", "user.email", "pa-test@example.invalid")
	if err := os.WriteFile(filepath.Join(store.PasswordsDir, ".gitattributes"), []byte("*.age binary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, store.PasswordsDir, "add", ".gitattributes")
	runGit(t, store.PasswordsDir, "commit", "-qm", "initial commit")

	enabled, err := store.RequireCleanGit()
	if err != nil || !enabled {
		t.Fatalf("RequireCleanGit() = %v, %v, want true, nil", enabled, err)
	}

	writeEntry(t, store, "imported", []byte("ciphertext"))
	if _, err := store.RequireCleanGit(); !errors.Is(err, ErrDirtyGit) {
		t.Fatalf("dirty RequireCleanGit() error = %v, want ErrDirtyGit", err)
	}
	runGit(t, store.PasswordsDir, "add", "imported.age")
	runGit(t, store.PasswordsDir, "commit", "-qm", "prepare")

	writeEntry(t, store, "second", []byte("second ciphertext"))
	if err := store.Commit([]string{"second"}, "sync entries"); err != nil {
		t.Fatal(err)
	}
	if subject := runGit(t, store.PasswordsDir, "log", "-1", "--format=%s"); subject != "sync entries" {
		t.Fatalf("commit subject = %q", subject)
	}
}

func runGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(bytes.TrimSpace(output))
}
