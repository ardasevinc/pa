package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/peerregistry"
	"github.com/ardasevinc/pa/internal/remote"
	"github.com/ardasevinc/pa/internal/store"
)

const peerCLITestFingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type peerCLIFixture struct {
	local  string
	remote string
	ssh    string
	age    agecmd.Tool
}

func newPeerCLIFixture(t *testing.T, withGit bool) *peerCLIFixture {
	t.Helper()
	age, err := agecmd.Find("")
	if err != nil {
		t.Skip(err)
	}
	keygen := findPeerKeygen(t)
	local := createPeerStore(t, keygen, withGit)
	remoteStore := createPeerStore(t, keygen, withGit)
	ssh := filepath.Join(t.TempDir(), "ssh")
	shim := "#!/bin/sh\nexec \"$PA_TEST_BINARY\" -test.run=TestPeerCLIHelperProcess\n"
	if err := os.WriteFile(ssh, []byte(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PA_TEST_PEER_HELPER", "1")
	t.Setenv("PA_TEST_BINARY", os.Args[0])
	t.Setenv("PA_TEST_REMOTE_STORE", remoteStore)
	return &peerCLIFixture{local: local, remote: remoteStore, ssh: ssh, age: age}
}

func createPeerStore(t *testing.T, keygen string, withGit bool) string {
	t.Helper()
	directory := t.TempDir()
	passwords := filepath.Join(directory, "passwords")
	if err := os.Mkdir(passwords, 0o700); err != nil {
		t.Fatal(err)
	}
	runPeerCommand(t, keygen, "-o", filepath.Join(directory, "identities"))
	runPeerCommand(t, keygen, "-y", "-o", filepath.Join(directory, "recipients"), filepath.Join(directory, "identities"))
	if withGit {
		runPeerCommand(t, "git", "-C", passwords, "init", "-q")
		runPeerCommand(t, "git", "-C", passwords, "config", "user.name", "pa peer test")
		runPeerCommand(t, "git", "-C", passwords, "config", "user.email", "pa-peer@example.invalid")
		if err := os.WriteFile(filepath.Join(passwords, ".gitattributes"), []byte("*.age binary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runPeerCommand(t, "git", "-C", passwords, "add", ".gitattributes")
		runPeerCommand(t, "git", "-C", passwords, "commit", "-qm", "initial commit")
	}
	return directory
}

func TestPeerCLIHelperProcess(t *testing.T) {
	if os.Getenv("PA_TEST_PEER_HELPER") != "1" {
		return
	}
	sshCount := 0
	if countPath := os.Getenv("PA_TEST_SSH_COUNT"); countPath != "" {
		file, err := os.OpenFile(countPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			os.Exit(88)
		}
		_, writeErr := file.WriteString("1\n")
		if err := errors.Join(writeErr, file.Close()); err != nil {
			os.Exit(89)
		}
		data, err := os.ReadFile(countPath)
		if err != nil {
			os.Exit(92)
		}
		sshCount = bytes.Count(data, []byte("\n"))
		if err := blockPeerSSH(sshCount, "PA_TEST_BLOCK_SSH_AT"); err != nil {
			os.Exit(93)
		}
	}
	age, err := agecmd.Find("")
	if err != nil {
		os.Exit(90)
	}
	if err := remote.Serve(context.Background(), age, os.Getenv("PA_TEST_REMOTE_STORE"), os.Stdin, os.Stdout); err != nil {
		os.Exit(91)
	}
	if err := blockPeerSSH(sshCount, "PA_TEST_BLOCK_SSH_AFTER_AT"); err != nil {
		os.Exit(94)
	}
	os.Exit(0)
}

func blockPeerSSH(count int, variable string) error {
	blockAt, _ := strconv.Atoi(os.Getenv(variable))
	if blockAt == 0 || blockAt != count {
		return nil
	}
	signal := os.Getenv("PA_TEST_BLOCK_SIGNAL")
	release := os.Getenv("PA_TEST_BLOCK_RELEASE")
	if err := os.WriteFile(signal, []byte("blocked\n"), 0o600); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(release); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if time.Now().After(deadline) {
			return errors.New("timed out waiting for SSH helper release")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPeerAddListShowAndRemove(t *testing.T) {
	fixture := newPeerCLIFixture(t, false)
	fingerprint := peerStoreFingerprint(t, fixture.remote)
	code, stdout, stderr := runPeerCLI(t, []string{
		"peer", "add", "devbox",
		"--host", "test-host",
		"--ssh", fixture.ssh,
		"--fingerprint", fingerprint,
		"--store", fixture.local,
		"--json",
	}, "", false)
	if code != 0 {
		t.Fatalf("peer add code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, `"name":"devbox"`) || !strings.Contains(stdout, fingerprint) {
		t.Fatalf("peer add JSON = %q", stdout)
	}

	code, stdout, stderr = runPeerCLI(t, []string{"peer", "list", "--store", fixture.local}, "", false)
	if code != 0 || !strings.Contains(stdout, "devbox\ttest-host\t"+fingerprint) {
		t.Fatalf("peer list = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr = runPeerCLI(t, []string{"peer", "show", "devbox", "--store", fixture.local}, "", false)
	if code != 0 || !strings.Contains(stdout, "name: devbox") || !strings.Contains(stdout, "host: test-host") {
		t.Fatalf("peer show = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, _, stderr = runPeerCLI(t, []string{"peer", "remove", "devbox", "--store", fixture.local}, "", false)
	if code == 0 || !strings.Contains(stderr, "requires --yes") {
		t.Fatalf("noninteractive peer remove = code %d, stderr %q", code, stderr)
	}
	code, stdout, stderr = runPeerCLI(t, []string{"peer", "remove", "devbox", "--store", fixture.local, "--yes"}, "", false)
	if code != 0 || stdout != "removed peer \"devbox\"\n" {
		t.Fatalf("peer remove = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr = runPeerCLI(t, []string{"peer", "list", "--store", fixture.local}, "", false)
	if code != 0 || stdout != "no peers\n" {
		t.Fatalf("empty peer list = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestPeerAddInteractiveConfirmation(t *testing.T) {
	t.Run("exact phrase", func(t *testing.T) {
		fixture := newPeerCLIFixture(t, false)
		code, _, stderr := runPeerCLI(t, []string{
			"peer", "add", "devbox", "--host", "test-host", "--ssh", fixture.ssh, "--store", fixture.local,
		}, "add devbox\n", true)
		if code != 0 {
			t.Fatalf("interactive add code = %d, stderr = %q", code, stderr)
		}
	})
	t.Run("wrong phrase", func(t *testing.T) {
		fixture := newPeerCLIFixture(t, false)
		code, _, stderr := runPeerCLI(t, []string{
			"peer", "add", "devbox", "--host", "test-host", "--ssh", fixture.ssh, "--store", fixture.local,
		}, "yes\n", true)
		if code == 0 || !strings.Contains(stderr, "confirmation did not match") {
			t.Fatalf("cancelled add code = %d, stderr = %q", code, stderr)
		}
		assertUnknownPeer(t, fixture.local, "devbox")
	})
	t.Run("noninteractive requires pin", func(t *testing.T) {
		fixture := newPeerCLIFixture(t, false)
		code, _, stderr := runPeerCLI(t, []string{
			"peer", "add", "devbox", "--host", "test-host", "--ssh", fixture.ssh, "--store", fixture.local,
		}, "", false)
		if code == 0 || !strings.Contains(stderr, "requires --fingerprint") {
			t.Fatalf("noninteractive add code = %d, stderr = %q", code, stderr)
		}
		assertUnknownPeer(t, fixture.local, "devbox")
	})
}

func TestPeerAddMismatchAndCollisionPreserveRegistry(t *testing.T) {
	fixture := newPeerCLIFixture(t, false)
	wrong := "sha256:" + strings.Repeat("0", 64)
	code, _, stderr := runPeerCLI(t, []string{
		"peer", "add", "devbox", "--host", "test-host", "--ssh", fixture.ssh,
		"--fingerprint", wrong, "--store", fixture.local,
	}, "", false)
	if code == 0 || !strings.Contains(stderr, "does not match") {
		t.Fatalf("mismatched add code = %d, stderr = %q", code, stderr)
	}
	assertUnknownPeer(t, fixture.local, "devbox")

	fingerprint := peerStoreFingerprint(t, fixture.remote)
	code, _, stderr = runPeerCLI(t, []string{
		"peer", "add", "devbox", "--host", "test-host", "--ssh", fixture.ssh,
		"--fingerprint", fingerprint, "--store", fixture.local,
	}, "", false)
	if code != 0 {
		t.Fatalf("first add code = %d, stderr = %q", code, stderr)
	}
	code, _, stderr = runPeerCLI(t, []string{
		"peer", "add", "devbox", "--host", "other-host", "--ssh", "/does/not/exist",
		"--fingerprint", fingerprint, "--store", fixture.local,
	}, "", false)
	if code == 0 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("duplicate add code = %d, stderr = %q", code, stderr)
	}
	record := readPeerRecord(t, fixture.local, "devbox")
	if record.Host != "test-host" {
		t.Fatalf("duplicate add changed host to %q", record.Host)
	}
}

func TestPeerReplaceRequiresVerifiedObservedFingerprint(t *testing.T) {
	fixture := newPeerCLIFixture(t, false)
	oldFingerprint := peerStoreFingerprint(t, fixture.remote)
	addPeerForTest(t, fixture, oldFingerprint)

	keygen := findPeerKeygen(t)
	runPeerCommand(t, keygen, "-o", filepath.Join(fixture.remote, "new-identities"))
	newRecipients := filepath.Join(fixture.remote, "new-recipients")
	runPeerCommand(t, keygen, "-y", "-o", newRecipients, filepath.Join(fixture.remote, "new-identities"))
	if err := os.Rename(newRecipients, filepath.Join(fixture.remote, "recipients")); err != nil {
		t.Fatal(err)
	}
	newFingerprint := peerStoreFingerprint(t, fixture.remote)

	code, _, stderr := runPeerCLI(t, []string{
		"peer", "replace", "devbox", "--ssh", fixture.ssh, "--fingerprint", oldFingerprint, "--store", fixture.local,
	}, "", false)
	if code == 0 || !strings.Contains(stderr, "does not match") {
		t.Fatalf("mismatched replace code = %d, stderr = %q", code, stderr)
	}
	if actual := readPeerRecord(t, fixture.local, "devbox").Fingerprint; actual != oldFingerprint {
		t.Fatalf("failed replace changed fingerprint to %s", actual)
	}

	code, stdout, stderr := runPeerCLI(t, []string{
		"peer", "replace", "devbox", "--ssh", fixture.ssh, "--fingerprint", newFingerprint, "--store", fixture.local,
	}, "", false)
	if code != 0 || stdout != "replaced peer \"devbox\"\n" {
		t.Fatalf("replace code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if actual := readPeerRecord(t, fixture.local, "devbox").Fingerprint; actual != newFingerprint {
		t.Fatalf("replace fingerprint = %s, want %s", actual, newFingerprint)
	}
}

func TestNamedPeerSyncEndToEndAndRepeat(t *testing.T) {
	fixture := newPeerCLIFixture(t, true)
	writePeerEntry(t, fixture.age, fixture.local, "local-only", []byte{'l', 0, 0xff})
	writePeerEntry(t, fixture.age, fixture.remote, "remote-only", []byte{})
	addPeerForTest(t, fixture, peerStoreFingerprint(t, fixture.remote))

	arguments := []string{"sync", "devbox", "--store", fixture.local, "--ssh", fixture.ssh, "--json"}
	code, stdout, stderr := runPeerCLI(t, arguments, "", false)
	if code != 0 {
		t.Fatalf("named sync code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, `"peer_name":"devbox"`) || !strings.Contains(stdout, `"imported":1`) {
		t.Fatalf("named sync JSON = %q", stdout)
	}
	if actual := readPeerEntry(t, fixture.age, fixture.local, "remote-only"); len(actual) != 0 {
		t.Fatalf("local empty entry = %q", actual)
	}
	if actual := readPeerEntry(t, fixture.age, fixture.remote, "local-only"); !bytes.Equal(actual, []byte{'l', 0, 0xff}) {
		t.Fatalf("remote binary entry = %q", actual)
	}

	code, stdout, stderr = runPeerCLI(t, arguments, "", false)
	if code != 0 || !strings.Contains(stdout, `"imported":0`) || !strings.Contains(stdout, `"skipped":2`) {
		t.Fatalf("repeat sync = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, stdout, stderr = runPeerCLI(t, []string{
		"sync", "--host", "test-host", "--peer-fingerprint", strings.ToUpper(peerStoreFingerprint(t, fixture.remote)),
		"--store", fixture.local, "--ssh", fixture.ssh, "--json",
	}, "", false)
	if code != 0 || strings.Contains(stdout, `"peer_name"`) || !strings.Contains(stdout, `"imported":0`) {
		t.Fatalf("low-level compatibility sync = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestNamedPeerMismatchAndUnknownAbortBeforePush(t *testing.T) {
	fixture := newPeerCLIFixture(t, true)
	countPath := filepath.Join(t.TempDir(), "ssh-count")
	t.Setenv("PA_TEST_SSH_COUNT", countPath)
	wrong := "sha256:" + strings.Repeat("0", 64)
	opened, err := store.Open(fixture.local)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := peerregistry.Open(opened)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(peerregistry.Record{Version: peerregistry.Version, Name: "devbox", Host: "test-host", Fingerprint: wrong}); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(registry.Close(), opened.Close()); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runPeerCLI(t, []string{"sync", "devbox", "--store", fixture.local, "--ssh", fixture.ssh}, "", false)
	if code == 0 || !strings.Contains(stderr, "no password data was sent") {
		t.Fatalf("mismatched sync code = %d, stderr = %q", code, stderr)
	}
	count, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "1\n" {
		t.Fatalf("mismatch spawned %q SSH requests, want one recipient probe", count)
	}

	code, _, stderr = runPeerCLI(t, []string{"sync", "missing", "--store", fixture.local, "--ssh", "/does/not/exist"}, "", false)
	if code == 0 || !strings.Contains(stderr, "unknown peer") {
		t.Fatalf("unknown sync code = %d, stderr = %q", code, stderr)
	}
}

func TestNamedPeerSyncHoldsTrustLeaseThroughPush(t *testing.T) {
	fixture := newPeerCLIFixture(t, true)
	writePeerEntry(t, fixture.age, fixture.local, "local-only", []byte("secret"))
	fingerprint := peerStoreFingerprint(t, fixture.remote)
	addPeerForTest(t, fixture, fingerprint)

	control := t.TempDir()
	countPath := filepath.Join(control, "count")
	signalPath := filepath.Join(control, "blocked")
	releasePath := filepath.Join(control, "release")
	t.Setenv("PA_TEST_SSH_COUNT", countPath)
	t.Setenv("PA_TEST_BLOCK_SSH_AT", "2")
	t.Setenv("PA_TEST_BLOCK_SIGNAL", signalPath)
	t.Setenv("PA_TEST_BLOCK_RELEASE", releasePath)

	type outcome struct {
		code           int
		stdout, stderr string
	}
	done := make(chan outcome, 1)
	go func() {
		code, stdout, stderr := runPeerCLI(t, []string{
			"sync", "devbox", "--store", fixture.local, "--ssh", fixture.ssh,
		}, "", false)
		done <- outcome{code: code, stdout: stdout, stderr: stderr}
	}()
	waitForFile(t, signalPath)

	opened, err := store.Open(fixture.local)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := peerregistry.Open(opened)
	if err != nil {
		t.Fatal(err)
	}
	current, err := registry.Get("devbox")
	if err != nil {
		t.Fatal(err)
	}
	replacement := current
	replacement.Host = "replacement-host"
	if err := registry.Replace(current, replacement); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("Replace() during named push error = %v, want ErrLocked", err)
	}
	if err := errors.Join(registry.Close(), opened.Close()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releasePath, []byte("release\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-done:
		if result.code != 0 {
			t.Fatalf("named sync code = %d, stdout = %q, stderr = %q", result.code, result.stdout, result.stderr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("named sync did not finish after releasing SSH shim")
	}
	if actual := readPeerRecord(t, fixture.local, "devbox"); actual != current {
		t.Fatalf("failed concurrent replacement changed peer to %+v", actual)
	}
}

func TestNamedPeerChangeAfterProbeAbortsBeforeDecrypt(t *testing.T) {
	fixture := newPeerCLIFixture(t, true)
	writePeerEntry(t, fixture.age, fixture.local, "local-only", []byte("secret"))
	addPeerForTest(t, fixture, peerStoreFingerprint(t, fixture.remote))

	control := t.TempDir()
	countPath := filepath.Join(control, "count")
	signalPath := filepath.Join(control, "blocked")
	releasePath := filepath.Join(control, "release")
	ageLog := filepath.Join(control, "age-log")
	ageWrapper := filepath.Join(control, "age")
	wrapper := fmt.Sprintf("#!/bin/sh\nprintf 'invoked\\n' >> \"$PA_TEST_AGE_LOG\"\nexec %q \"$@\"\n", fixture.age.Path)
	if err := os.WriteFile(ageWrapper, []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PA_TEST_SSH_COUNT", countPath)
	t.Setenv("PA_TEST_BLOCK_SSH_AFTER_AT", "1")
	t.Setenv("PA_TEST_BLOCK_SIGNAL", signalPath)
	t.Setenv("PA_TEST_BLOCK_RELEASE", releasePath)
	t.Setenv("PA_TEST_AGE_LOG", ageLog)

	type outcome struct {
		code           int
		stdout, stderr string
	}
	done := make(chan outcome, 1)
	go func() {
		code, stdout, stderr := runPeerCLI(t, []string{
			"sync", "devbox", "--store", fixture.local, "--ssh", fixture.ssh, "--age", ageWrapper,
		}, "", false)
		done <- outcome{code: code, stdout: stdout, stderr: stderr}
	}()
	waitForFile(t, signalPath)

	opened, err := store.Open(fixture.local)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := peerregistry.Open(opened)
	if err != nil {
		t.Fatal(err)
	}
	current, err := registry.Get("devbox")
	if err != nil {
		t.Fatal(err)
	}
	replacement := current
	replacement.Host = "replacement-host"
	if err := registry.Replace(current, replacement); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(registry.Close(), opened.Close()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releasePath, []byte("release\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-done:
		if result.code == 0 || !strings.Contains(result.stderr, "changed while sync was starting") || !strings.Contains(result.stderr, "no password data was sent") {
			t.Fatalf("changed-peer sync = code %d, stdout %q, stderr %q", result.code, result.stdout, result.stderr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("changed-peer sync did not finish")
	}
	if _, err := os.Stat(ageLog); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("age command ran before changed-peer abort: %v", err)
	}
	count, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "1\n" {
		t.Fatalf("changed-peer sync spawned %q SSH requests, want one", count)
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("writer failed") }

func TestPeerAuthorizationRequiresVisiblePrompt(t *testing.T) {
	record := peerregistry.Record{Version: peerregistry.Version, Name: "devbox", Host: "host", Fingerprint: peerCLITestFingerprint}
	err := authorizePeer("add", record, nil, "", strings.NewReader("add devbox\n"), true, false, failedWriter{})
	if err == nil || !strings.Contains(err.Error(), "write confirmation prompt") {
		t.Fatalf("authorizePeer() error = %v", err)
	}
}

func TestPeerMutationOutputFailureReportsApplied(t *testing.T) {
	fixture := newPeerCLIFixture(t, false)
	fingerprint := peerStoreFingerprint(t, fixture.remote)
	err := runPeerAdd(t.Context(), []string{
		"devbox", "--host", "test-host", "--ssh", fixture.ssh,
		"--fingerprint", fingerprint, "--store", fixture.local,
	}, strings.NewReader(""), false, failedWriter{}, io.Discard)
	var applied *peerregistry.AppliedError
	if !errors.As(err, &applied) {
		t.Fatalf("runPeerAdd() error = %v, want AppliedError", err)
	}
	if actual := readPeerRecord(t, fixture.local, "devbox"); actual.Fingerprint != fingerprint {
		t.Fatalf("applied add record = %+v", actual)
	}
}

func TestSyncOutputFailureReportsApplied(t *testing.T) {
	fixture := newPeerCLIFixture(t, true)
	writePeerEntry(t, fixture.age, fixture.local, "local-only", []byte("secret"))
	addPeerForTest(t, fixture, peerStoreFingerprint(t, fixture.remote))

	var stderr bytes.Buffer
	code := runWithInput(t.Context(), []string{
		"sync", "devbox", "--store", fixture.local, "--ssh", fixture.ssh,
	}, strings.NewReader(""), false, failedWriter{}, &stderr)
	if code != 3 || !strings.Contains(stderr.String(), "sync entries were applied") {
		t.Fatalf("sync output failure = code %d, stderr %q", code, stderr.String())
	}
	if actual := readPeerEntry(t, fixture.age, fixture.remote, "local-only"); !bytes.Equal(actual, []byte("secret")) {
		t.Fatalf("remote entry after applied output failure = %q", actual)
	}
}

func TestSavedAndLowLevelSyncArgumentsCannotMix(t *testing.T) {
	for _, arguments := range [][]string{
		{"sync", "devbox", "--host", "evil.example"},
		{"sync", "devbox", "--peer-fingerprint", peerCLITestFingerprint},
		{"sync", "devbox", "--ssh-option=-p"},
	} {
		code, _, stderr := runPeerCLI(t, arguments, "", false)
		if code == 0 || !strings.Contains(stderr, "cannot be combined") {
			t.Errorf("run(%v) = code %d, stderr %q", arguments, code, stderr)
		}
	}
}

func runPeerCLI(t *testing.T, arguments []string, input string, interactive bool) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWithInput(t.Context(), arguments, strings.NewReader(input), interactive, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func waitForFile(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(name); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			t.Fatalf("wait for %s: %v", name, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func addPeerForTest(t *testing.T, fixture *peerCLIFixture, fingerprint string) {
	t.Helper()
	code, _, stderr := runPeerCLI(t, []string{
		"peer", "add", "devbox", "--host", "test-host", "--ssh", fixture.ssh,
		"--fingerprint", fingerprint, "--store", fixture.local,
	}, "", false)
	if code != 0 {
		t.Fatalf("add peer fixture code = %d, stderr = %q", code, stderr)
	}
}

func assertUnknownPeer(t *testing.T, directory, name string) {
	t.Helper()
	opened, err := store.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := peerregistry.Open(opened)
	if err != nil {
		t.Fatal(err)
	}
	_, getErr := registry.Get(name)
	if err := errors.Join(registry.Close(), opened.Close()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(getErr, peerregistry.ErrNotFound) {
		t.Fatalf("Get(%s) error = %v, want ErrNotFound", name, getErr)
	}
}

func readPeerRecord(t *testing.T, directory, name string) peerregistry.Record {
	t.Helper()
	opened, err := store.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := peerregistry.Open(opened)
	if err != nil {
		t.Fatal(err)
	}
	record, getErr := registry.Get(name)
	if err := errors.Join(getErr, registry.Close(), opened.Close()); err != nil {
		t.Fatal(err)
	}
	return record
}

func peerStoreFingerprint(t *testing.T, directory string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, "recipients"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func writePeerEntry(t *testing.T, age agecmd.Tool, directory, name string, value []byte) {
	t.Helper()
	opened, err := store.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	entryPath, err := opened.EntryPath(name)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := age.StartEncrypt(t.Context(), opened.RecipientsPath, entryPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	relative, _ := filepath.Rel(filepath.Join(directory, "passwords"), entryPath)
	runPeerCommand(t, "git", "-C", filepath.Join(directory, "passwords"), "add", relative)
	runPeerCommand(t, "git", "-C", filepath.Join(directory, "passwords"), "commit", "-qm", "add "+name)
}

func readPeerEntry(t *testing.T, age agecmd.Tool, directory, name string) []byte {
	t.Helper()
	opened, err := store.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	entryPath, err := opened.EntryPath(name)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := age.StartDecrypt(t.Context(), opened.IdentitiesPath, entryPath)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(reader)
	if err := errors.Join(readErr, reader.Close(), opened.Close()); err != nil {
		t.Fatal(err)
	}
	return data
}

func findPeerKeygen(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"age-keygen", "rage-keygen"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	t.Skip("age-keygen or rage-keygen not installed")
	return ""
}

func runPeerCommand(t *testing.T, command string, arguments ...string) {
	t.Helper()
	if output, err := exec.Command(command, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", command, arguments, err, output)
	}
}
