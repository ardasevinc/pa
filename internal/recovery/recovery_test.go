package recovery

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/store"
)

type recoveryFixture struct {
	store *store.Store
	age   agecmd.Tool
}

func newRecoveryFixture(t *testing.T, age agecmd.Tool) *recoveryFixture {
	t.Helper()
	directory := t.TempDir()
	passwords := filepath.Join(directory, "passwords")
	if err := os.Mkdir(passwords, 0o700); err != nil {
		t.Fatal(err)
	}
	keygen := findKeygen(t)
	run(t, keygen, "-o", filepath.Join(directory, "identities"))
	run(t, keygen, "-y", "-o", filepath.Join(directory, "recipients"), filepath.Join(directory, "identities"))
	runGit(t, passwords, "init", "-q")
	runGit(t, passwords, "config", "user.name", "pa recovery test")
	runGit(t, passwords, "config", "user.email", "pa-recovery@example.invalid")
	if err := os.WriteFile(filepath.Join(passwords, ".gitattributes"), []byte("*.age binary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, passwords, "add", ".gitattributes")
	runGit(t, passwords, "commit", "-qm", "initial commit")
	opened, err := store.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return &recoveryFixture{store: opened, age: age}
}

func (f *recoveryFixture) write(t *testing.T, name string, value []byte) {
	t.Helper()
	entryPath := f.encrypt(t, name, value)
	relative, _ := filepath.Rel(f.store.PasswordsDir, entryPath)
	runGit(t, f.store.PasswordsDir, "add", relative)
	runGit(t, f.store.PasswordsDir, "commit", "-qm", "write "+name)
}

func (f *recoveryFixture) encrypt(t *testing.T, name string, value []byte) string {
	t.Helper()
	entryPath, err := f.store.EntryPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(entryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(entryPath), ".recovery-test-*.age")
	if err != nil {
		t.Fatal(err)
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		t.Fatal(err)
	}
	writer, err := f.age.StartEncrypt(t.Context(), f.store.RecipientsPath, temporaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporaryPath, entryPath); err != nil {
		t.Fatal(err)
	}
	return entryPath
}

func (f *recoveryFixture) remove(t *testing.T, name string) {
	t.Helper()
	entryPath, _ := f.store.EntryPath(name)
	if err := os.Remove(entryPath); err != nil {
		t.Fatal(err)
	}
	relative, _ := filepath.Rel(f.store.PasswordsDir, entryPath)
	runGit(t, f.store.PasswordsDir, "add", relative)
	runGit(t, f.store.PasswordsDir, "commit", "-qm", "remove "+name)
}

func (f *recoveryFixture) read(t *testing.T, name string) []byte {
	t.Helper()
	entryPath, _ := f.store.EntryPath(name)
	reader, err := f.age.StartDecrypt(t.Context(), f.store.IdentitiesPath, entryPath)
	if err != nil {
		t.Fatal(err)
	}
	value, readErr := io.ReadAll(reader)
	if err := errors.Join(readErr, reader.Close()); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestRestoreExactBackupSet(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	fixture := newRecoveryFixture(t, age)
	fixture.write(t, "alpha", []byte{'o', 'l', 'd', 0, 0xff})
	fixture.write(t, "nested/extra", []byte{})
	identitiesBefore, _ := os.ReadFile(fixture.store.IdentitiesPath)
	recipientsBefore, _ := os.ReadFile(fixture.store.RecipientsPath)
	const sourceID = "source-backup"
	if _, err := fixture.store.Snapshot(sourceID, "before"); err != nil {
		t.Fatal(err)
	}

	fixture.write(t, "alpha", []byte("new"))
	fixture.remove(t, "nested/extra")
	fixture.write(t, "newer", []byte("remove me"))
	result, err := Restore(t.Context(), age, fixture.store, sourceID, "before")
	if err != nil {
		t.Fatal(err)
	}
	if result.Restored != 2 || result.Removed != 1 || !result.GitCommitted {
		t.Fatalf("Restore() result = %+v", result)
	}
	if result.BackupBefore == "" || result.BackupAfter == "" || result.Receipt == "" {
		t.Fatalf("Restore() recovery artifacts = %+v", result)
	}
	if !bytes.Equal(fixture.read(t, "alpha"), []byte{'o', 'l', 'd', 0, 0xff}) {
		t.Fatal("alpha did not return to exact backup value")
	}
	if !bytes.Equal(fixture.read(t, "nested/extra"), []byte{}) {
		t.Fatal("empty backup entry was not restored")
	}
	if exists, err := fixture.store.Exists("newer"); err != nil || exists {
		t.Fatalf("post-backup entry remains: exists=%v err=%v", exists, err)
	}
	identitiesAfter, _ := os.ReadFile(fixture.store.IdentitiesPath)
	recipientsAfter, _ := os.ReadFile(fixture.store.RecipientsPath)
	if !bytes.Equal(identitiesBefore, identitiesAfter) || !bytes.Equal(recipientsBefore, recipientsAfter) {
		t.Fatal("restore changed local age identity or recipients")
	}
	if _, err := fixture.store.RequireCleanGit(); err != nil {
		t.Fatalf("restored Git repository is dirty: %v", err)
	}
	repeated, err := Restore(t.Context(), age, fixture.store, sourceID, "before")
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Restored != 0 || repeated.Removed != 0 || repeated.BackupBefore != "" {
		t.Fatalf("repeated Restore() result = %+v", repeated)
	}
	backups, err := List(fixture.store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var restoreBackup *Backup
	for index := range backups {
		if backups[index].TransactionID == result.TransactionID {
			restoreBackup = &backups[index]
		}
	}
	if len(backups) != 2 || restoreBackup == nil || !restoreBackup.Before || !restoreBackup.After || !restoreBackup.Receipt {
		t.Fatalf("List() = %+v", backups)
	}
}

func TestRestoreRefusesDirtyStoreAndCorruptBackup(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	fixture := newRecoveryFixture(t, age)
	fixture.write(t, "preserved", []byte("keep"))
	const sourceID = "source-backup"
	snapshot, err := fixture.store.Snapshot(sourceID, "before")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.store.PasswordsDir, "dirty"), []byte("dirty"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(t.Context(), age, fixture.store, sourceID, "before"); !errors.Is(err, store.ErrDirtyGit) {
		t.Fatalf("dirty Restore() error = %v", err)
	}
	if err := os.Remove(filepath.Join(fixture.store.PasswordsDir, "dirty")); err != nil {
		t.Fatal(err)
	}
	backupEntry := filepath.Join(snapshot, "preserved.age")
	if err := os.WriteFile(backupEntry, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(t.Context(), age, fixture.store, sourceID, "before"); err == nil {
		t.Fatal("Restore() accepted corrupt backup ciphertext")
	}
	if !bytes.Equal(fixture.read(t, "preserved"), []byte("keep")) {
		t.Fatal("failed restore changed current entry")
	}
}

func TestRestoreAllowDirtyContinuesInterruptedWork(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	fixture := newRecoveryFixture(t, age)
	fixture.write(t, "entry", []byte("backup value"))
	const sourceID = "source-backup"
	if _, err := fixture.store.Snapshot(sourceID, "before"); err != nil {
		t.Fatal(err)
	}
	fixture.write(t, "entry", []byte("later committed value"))
	fixture.encrypt(t, "entry", []byte("interrupted uncommitted value"))
	if _, err := fixture.store.RequireCleanGit(); !errors.Is(err, store.ErrDirtyGit) {
		t.Fatalf("fixture is not dirty: %v", err)
	}

	result, err := RestoreWithOptions(t.Context(), age, fixture.store, sourceID, "before", RestoreOptions{AllowDirty: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Restored != 1 || !result.GitCommitted {
		t.Fatalf("RestoreWithOptions() result = %+v", result)
	}
	if !bytes.Equal(fixture.read(t, "entry"), []byte("backup value")) {
		t.Fatal("dirty continuation did not converge to backup value")
	}
	if _, err := fixture.store.RequireCleanGit(); err != nil {
		t.Fatalf("continued restore did not clean its entry change: %v", err)
	}
}

func findKeygen(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"age-keygen", "rage-keygen"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	t.Skip("age-keygen or rage-keygen not installed")
	return ""
}

func run(t *testing.T, command string, arguments ...string) {
	t.Helper()
	if output, err := exec.Command(command, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", command, arguments, err, output)
	}
}

func runGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	run(t, "git", append([]string{"-C", directory}, arguments...)...)
}
