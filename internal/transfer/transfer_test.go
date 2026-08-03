package transfer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/store"
)

type transferFixture struct {
	store *store.Store
	age   agecmd.Tool
}

func newTransferFixture(t *testing.T, age agecmd.Tool) *transferFixture {
	t.Helper()
	directory := t.TempDir()
	passwords := filepath.Join(directory, "passwords")
	if err := os.Mkdir(passwords, 0o700); err != nil {
		t.Fatal(err)
	}
	keygen := findKeygen(t)
	identities := filepath.Join(directory, "identities")
	recipients := filepath.Join(directory, "recipients")
	runCommand(t, keygen, "-o", identities)
	runCommand(t, keygen, "-y", "-o", recipients, identities)

	runGit(t, passwords, "init", "-q")
	runGit(t, passwords, "config", "user.name", "pa transfer test")
	runGit(t, passwords, "config", "user.email", "pa-transfer@example.invalid")
	if err := os.WriteFile(filepath.Join(passwords, ".gitattributes"), []byte("*.age binary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, passwords, "add", ".gitattributes")
	runGit(t, passwords, "commit", "-qm", "initial commit")

	opened, err := store.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return &transferFixture{store: opened, age: age}
}

func (f *transferFixture) add(t *testing.T, name string, value []byte) {
	t.Helper()
	entryPath, err := f.store.EntryPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(entryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writer, err := f.age.StartEncrypt(context.Background(), f.store.RecipientsPath, entryPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(f.store.PasswordsDir, entryPath)
	if err != nil {
		t.Fatal(err)
	}
	runGit(t, f.store.PasswordsDir, "add", relative)
	runGit(t, f.store.PasswordsDir, "commit", "-qm", "add "+name)
}

func (f *transferFixture) read(t *testing.T, name string) []byte {
	t.Helper()
	entryPath, err := f.store.EntryPath(name)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := f.age.StartDecrypt(context.Background(), f.store.IdentitiesPath, entryPath)
	if err != nil {
		t.Fatal(err)
	}
	value, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestExportImportSetUnion(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	left := newTransferFixture(t, age)
	right := newTransferFixture(t, age)
	leftShared := []byte("left remains left\n")
	rightShared := []byte("right remains right\n")
	onlyLeft := []byte{'l', 0x00, 0xff, '\n', '\n'}
	onlyRight := []byte{}
	left.add(t, "shared", leftShared)
	left.add(t, "nested/only-left", onlyLeft)
	right.add(t, "shared", rightShared)
	right.add(t, "only-right", onlyRight)

	leftIdentity, err := os.ReadFile(left.store.IdentitiesPath)
	if err != nil {
		t.Fatal(err)
	}
	rightIdentity, err := os.ReadFile(right.store.IdentitiesPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(leftIdentity, rightIdentity) {
		t.Fatal("fixtures unexpectedly share an age identity")
	}

	directory := t.TempDir()
	leftBundle := filepath.Join(directory, "left-to-right.age")
	exported, err := Export(context.Background(), age, left.store, right.store.RecipientsPath, leftBundle)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Entries != 2 {
		t.Fatalf("Export() entries = %d, want 2", exported.Entries)
	}

	imported, err := Import(context.Background(), age, right.store, leftBundle)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Imported != 1 || imported.Skipped != 1 || !imported.GitCommitted {
		t.Fatalf("Import() result = %+v", imported)
	}
	if imported.BackupBefore == "" || imported.BackupAfter == "" || imported.Receipt == "" {
		t.Fatalf("Import() did not record recovery artifacts: %+v", imported)
	}
	if !bytes.Equal(right.read(t, "shared"), rightShared) {
		t.Fatal("right shared value was overwritten")
	}
	if !bytes.Equal(right.read(t, "nested/only-left"), onlyLeft) {
		t.Fatal("right did not receive exact left-only value")
	}

	rightBundle := filepath.Join(directory, "right-to-left.age")
	if _, err := Export(context.Background(), age, right.store, left.store.RecipientsPath, rightBundle); err != nil {
		t.Fatal(err)
	}
	imported, err = Import(context.Background(), age, left.store, rightBundle)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Imported != 1 || imported.Skipped != 2 {
		t.Fatalf("reverse Import() result = %+v", imported)
	}
	if !bytes.Equal(left.read(t, "shared"), leftShared) {
		t.Fatal("left shared value was overwritten")
	}
	if !bytes.Equal(left.read(t, "only-right"), onlyRight) {
		t.Fatal("left did not receive exact empty right-only value")
	}

	leftNames, err := left.store.List()
	if err != nil {
		t.Fatal(err)
	}
	rightNames, err := right.store.List()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftNames, rightNames) {
		t.Fatalf("union names differ: left=%v right=%v", leftNames, rightNames)
	}

	repeated, err := Import(context.Background(), age, left.store, rightBundle)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Imported != 0 || repeated.Skipped != 3 || repeated.BackupBefore != "" {
		t.Fatalf("repeated Import() result = %+v", repeated)
	}
}

func TestExportNeverOverwritesAndRejectsStoreOutput(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	source := newTransferFixture(t, age)
	destination := newTransferFixture(t, age)
	source.add(t, "entry", []byte("value"))

	output := filepath.Join(t.TempDir(), "existing.age")
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(context.Background(), age, source.store, destination.store.RecipientsPath, output); err == nil {
		t.Fatal("Export() overwrote an existing output")
	}
	actual, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, []byte("keep")) {
		t.Fatalf("existing export changed to %q", actual)
	}

	insideStore := filepath.Join(source.store.PasswordsDir, "export.age")
	if _, err := Export(context.Background(), age, source.store, destination.store.RecipientsPath, insideStore); err == nil {
		t.Fatal("Export() accepted output inside password store")
	}
}

func TestImportRejectsCorruptionWithoutMutation(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	source := newTransferFixture(t, age)
	destination := newTransferFixture(t, age)
	source.add(t, "entry", []byte("value"))
	destination.add(t, "preserved", []byte("keep"))

	bundle := filepath.Join(t.TempDir(), "bundle.age")
	if _, err := Export(context.Background(), age, source.store, destination.store.RecipientsPath, bundle); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(t.TempDir(), "truncated.age")
	if err := os.WriteFile(truncated, data[:len(data)-1], 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Import(context.Background(), age, destination.store, truncated); err == nil {
		t.Fatal("Import() accepted truncated ciphertext")
	}
	if exists, err := destination.store.Exists("entry"); err != nil || exists {
		t.Fatalf("corrupt import published entry: exists=%v err=%v", exists, err)
	}
	if !bytes.Equal(destination.read(t, "preserved"), []byte("keep")) {
		t.Fatal("corrupt import changed existing entry")
	}
}

func TestImportRefusesDirtyGitStore(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	source := newTransferFixture(t, age)
	destination := newTransferFixture(t, age)
	source.add(t, "entry", []byte("value"))
	bundle := filepath.Join(t.TempDir(), "bundle.age")
	if _, err := Export(context.Background(), age, source.store, destination.store.RecipientsPath, bundle); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination.store.PasswordsDir, "dirty"), []byte("dirty"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Import(context.Background(), age, destination.store, bundle); !errors.Is(err, store.ErrDirtyGit) {
		t.Fatalf("Import() error = %v, want ErrDirtyGit", err)
	}
	if exists, err := destination.store.Exists("entry"); err != nil || exists {
		t.Fatalf("dirty import published entry: exists=%v err=%v", exists, err)
	}
}

func TestExportCorruptSourceLeavesNoOutput(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	source := newTransferFixture(t, age)
	destination := newTransferFixture(t, age)
	source.add(t, "entry", []byte("value"))
	entryPath, _ := source.store.EntryPath("entry")
	if err := os.WriteFile(entryPath, []byte("not age ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle.age")

	if _, err := Export(context.Background(), age, source.store, destination.store.RecipientsPath, output); err == nil {
		t.Fatal("Export() accepted corrupt source ciphertext")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed export left output: %v", err)
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

func runCommand(t *testing.T, name string, arguments ...string) string {
	t.Helper()
	output, err := exec.Command(name, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, arguments, err, output)
	}
	return string(bytes.TrimSpace(output))
}

func runGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	return runCommand(t, "git", append([]string{"-C", directory}, arguments...)...)
}
