package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/store"
	"github.com/ardasevinc/pa/internal/transfer"
)

type remoteFixture struct {
	directory string
	store     *store.Store
	age       agecmd.Tool
}

func newRemoteFixture(t *testing.T, age agecmd.Tool) *remoteFixture {
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
	runGit(t, passwords, "config", "user.name", "pa remote test")
	runGit(t, passwords, "config", "user.email", "pa-remote@example.invalid")
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
	return &remoteFixture{directory: directory, store: opened, age: age}
}

func (f *remoteFixture) add(t *testing.T, name string, value []byte) {
	t.Helper()
	path, err := f.store.EntryPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writer, err := f.age.StartEncrypt(t.Context(), f.store.RecipientsPath, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	relative, _ := filepath.Rel(f.store.PasswordsDir, path)
	runGit(t, f.store.PasswordsDir, "add", relative)
	runGit(t, f.store.PasswordsDir, "commit", "-qm", "add "+name)
}

func (f *remoteFixture) read(t *testing.T, name string) []byte {
	t.Helper()
	path, err := f.store.EntryPath(name)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := f.age.StartDecrypt(t.Context(), f.store.IdentitiesPath, path)
	if err != nil {
		t.Fatal(err)
	}
	value, readErr := io.ReadAll(reader)
	if err := errors.Join(readErr, reader.Close()); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestServeRecipientPushPull(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	left := newRemoteFixture(t, age)
	right := newRemoteFixture(t, age)
	left.add(t, "left", []byte{'l', 0, 0xff})
	right.add(t, "right", []byte{})
	left.add(t, "shared", []byte("left"))
	right.add(t, "shared", []byte("right"))

	var request, response bytes.Buffer
	if err := writeRequest(&request, commandRecipient); err != nil {
		t.Fatal(err)
	}
	if err := Serve(t.Context(), age, right.directory, &request, &response); err != nil {
		t.Fatal(err)
	}
	status, err := readStatus(&response)
	if err != nil || status != statusOK {
		t.Fatalf("recipient status = %d, err = %v", status, err)
	}
	recipients, err := readBytes32(&response, maxRecipientBytes)
	if err != nil {
		t.Fatal(err)
	}
	wantRecipients, _ := os.ReadFile(right.store.RecipientsPath)
	if !bytes.Equal(recipients, wantRecipients) {
		t.Fatal("served recipient file differs")
	}

	bundle := filepath.Join(t.TempDir(), "push.age")
	if _, err := transfer.Export(t.Context(), age, left.store, right.store.RecipientsPath, bundle); err != nil {
		t.Fatal(err)
	}
	bundleData, _ := os.ReadFile(bundle)
	request.Reset()
	response.Reset()
	if err := writeRequest(&request, commandPush); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&request, binary.BigEndian, uint64(len(bundleData))); err != nil {
		t.Fatal(err)
	}
	request.Write(bundleData)
	if err := Serve(t.Context(), age, right.directory, &request, &response); err != nil {
		t.Fatal(err)
	}
	status, _ = readStatus(&response)
	if status != statusOK {
		message, _ := readBytes32(&response, maxMessageBytes)
		t.Fatalf("push status = %d: %s", status, message)
	}
	payload, err := readBytes32(&response, maxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	var envelope importEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.Imported != 1 || envelope.Result.Skipped != 1 {
		t.Fatalf("push result = %+v", envelope.Result)
	}
	if !bytes.Equal(right.read(t, "shared"), []byte("right")) {
		t.Fatal("push overwrote same-name destination entry")
	}

	leftRecipients, _ := os.ReadFile(left.store.RecipientsPath)
	request.Reset()
	response.Reset()
	if err := writeRequest(&request, commandPull); err != nil {
		t.Fatal(err)
	}
	if err := writeBytes32(&request, leftRecipients); err != nil {
		t.Fatal(err)
	}
	if err := Serve(context.Background(), age, right.directory, &request, &response); err != nil {
		t.Fatal(err)
	}
	status, _ = readStatus(&response)
	if status != statusOK {
		message, _ := readBytes32(&response, maxMessageBytes)
		t.Fatalf("pull status = %d: %s", status, message)
	}
	var pullLength uint64
	if err := binary.Read(&response, binary.BigEndian, &pullLength); err != nil {
		t.Fatal(err)
	}
	pulled := filepath.Join(t.TempDir(), "pull.age")
	file, err := os.OpenFile(pulled, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(file, &response, int64(pullLength)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := transfer.Import(t.Context(), age, left.store, pulled)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 || result.Skipped != 2 {
		t.Fatalf("pull import result = %+v", result)
	}
	if !bytes.Equal(left.read(t, "shared"), []byte("left")) {
		t.Fatal("pull overwrote same-name local entry")
	}
}

func TestServeRejectsOversizedPush(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	fixture := newRemoteFixture(t, age)
	var request, response bytes.Buffer
	if err := writeRequest(&request, commandPush); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&request, binary.BigEndian, maxBundleBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := Serve(t.Context(), age, fixture.directory, &request, &response); err != nil {
		t.Fatal(err)
	}
	status, _ := readStatus(&response)
	if status != statusError {
		t.Fatalf("oversized push status = %d", status)
	}
}

func TestClientOverSSHProcessBoundary(t *testing.T) {
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	local := newRemoteFixture(t, age)
	remoteStore := newRemoteFixture(t, age)
	local.add(t, "local", []byte{'a', 0, 'b'})
	remoteStore.add(t, "remote", []byte("remote"))

	sshShim := filepath.Join(t.TempDir(), "ssh")
	shim := "#!/bin/sh\nexec \"$PA_TEST_BINARY\" -test.run=TestSSHHelperProcess\n"
	if err := os.WriteFile(sshShim, []byte(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PA_TEST_SSH_HELPER", "1")
	t.Setenv("PA_TEST_BINARY", os.Args[0])
	t.Setenv("PA_TEST_REMOTE_STORE", remoteStore.directory)
	client := Client{Host: "test-host", SSHPath: sshShim}

	peer, err := client.Recipient(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	recipients, _ := os.ReadFile(remoteStore.store.RecipientsPath)
	digest := sha256.Sum256(recipients)
	if peer.Fingerprint != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatalf("peer fingerprint = %q", peer.Fingerprint)
	}

	pushBundle := filepath.Join(t.TempDir(), "push.age")
	if _, err := transfer.Export(t.Context(), age, local.store, remoteStore.store.RecipientsPath, pushBundle); err != nil {
		t.Fatal(err)
	}
	pushResult, err := client.Push(t.Context(), pushBundle)
	if err != nil {
		t.Fatal(err)
	}
	if pushResult.Imported != 1 {
		t.Fatalf("push result = %+v", pushResult)
	}
	if !bytes.Equal(remoteStore.read(t, "local"), []byte{'a', 0, 'b'}) {
		t.Fatal("remote did not receive exact pushed bytes")
	}

	localRecipients, _ := os.ReadFile(local.store.RecipientsPath)
	pullBundle := filepath.Join(t.TempDir(), "pull.age")
	if err := client.Pull(t.Context(), localRecipients, pullBundle); err != nil {
		t.Fatal(err)
	}
	pullResult, err := transfer.Import(t.Context(), age, local.store, pullBundle)
	if err != nil {
		t.Fatal(err)
	}
	if pullResult.Imported != 1 || !bytes.Equal(local.read(t, "remote"), []byte("remote")) {
		t.Fatalf("pull result = %+v", pullResult)
	}
}

func TestSSHHelperProcess(t *testing.T) {
	if os.Getenv("PA_TEST_SSH_HELPER") != "1" {
		return
	}
	age, err := agecmd.Find("")
	if err != nil {
		os.Exit(90)
	}
	if err := Serve(context.Background(), age, os.Getenv("PA_TEST_REMOTE_STORE"), os.Stdin, os.Stdout); err != nil {
		os.Exit(91)
	}
	os.Exit(0)
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
