package peerregistry

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ardasevinc/pa/internal/store"
)

const testFingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type registryFixture struct {
	directory string
	store     *store.Store
	registry  *Registry
}

func newRegistryFixture(t *testing.T) *registryFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "passwords"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identities", "recipients"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	opened, err := store.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := Open(opened)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(registry.Close(), opened.Close()); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	})
	return &registryFixture{directory: directory, store: opened, registry: registry}
}

func testRecord(name, host string) Record {
	return Record{Version: Version, Name: name, Host: host, Fingerprint: testFingerprint}
}

func TestListWithoutRegistryIsEmpty(t *testing.T) {
	fixture := newRegistryFixture(t)
	records, err := fixture.registry.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("List() = %+v, want empty", records)
	}
	if _, err := os.Lstat(filepath.Join(fixture.directory, "peers")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read-only list created peers directory: %v", err)
	}
}

func TestAddGetListAndModes(t *testing.T) {
	fixture := newRegistryFixture(t)
	second := testRecord("zeta", "zeta.example")
	first := testRecord("alpha", "alpha.example")
	if err := fixture.registry.Add(second); err != nil {
		t.Fatal(err)
	}
	if err := fixture.registry.Add(first); err != nil {
		t.Fatal(err)
	}
	actual, err := fixture.registry.Get("alpha")
	if err != nil || actual != first {
		t.Fatalf("Get(alpha) = %+v, %v", actual, err)
	}
	records, err := fixture.registry.List()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(records, []Record{first, second}) {
		t.Fatalf("List() = %+v", records)
	}
	for name, want := range map[string]fs.FileMode{"peers": 0o700, "peers/alpha.json": 0o600} {
		info, err := os.Stat(filepath.Join(fixture.directory, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if actual := info.Mode().Perm(); actual != want {
			t.Errorf("mode %s = %o, want %o", name, actual, want)
		}
	}
}

func TestAddNeverReplacesExistingPeer(t *testing.T) {
	fixture := newRegistryFixture(t)
	original := testRecord("devbox", "original.example")
	if err := fixture.registry.Add(original); err != nil {
		t.Fatal(err)
	}
	replacement := testRecord("devbox", "replacement.example")
	if err := fixture.registry.Add(replacement); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate Add() error = %v, want ErrExists", err)
	}
	actual, err := fixture.registry.Get("devbox")
	if err != nil || actual != original {
		t.Fatalf("duplicate add changed peer: %+v, %v", actual, err)
	}
}

func TestReplaceUsesCompareAndSwap(t *testing.T) {
	fixture := newRegistryFixture(t)
	original := testRecord("devbox", "original.example")
	if err := fixture.registry.Add(original); err != nil {
		t.Fatal(err)
	}
	replacement := testRecord("devbox", "replacement.example")
	stale := original
	stale.Host = "stale.example"
	if err := fixture.registry.Replace(stale, replacement); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale Replace() error = %v, want ErrChanged", err)
	}
	if err := fixture.registry.Replace(original, replacement); err != nil {
		t.Fatal(err)
	}
	actual, err := fixture.registry.Get("devbox")
	if err != nil || actual != replacement {
		t.Fatalf("Get() after replace = %+v, %v", actual, err)
	}
}

func TestRemoveUsesCompareAndSwap(t *testing.T) {
	fixture := newRegistryFixture(t)
	record := testRecord("devbox", "devbox.example")
	if err := fixture.registry.Add(record); err != nil {
		t.Fatal(err)
	}
	stale := record
	stale.Host = "stale.example"
	if err := fixture.registry.Remove(stale); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale Remove() error = %v, want ErrChanged", err)
	}
	if err := fixture.registry.Remove(record); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.registry.Get("devbox"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after remove error = %v, want ErrNotFound", err)
	}
}

func TestValidationRejectsUnsafeRecords(t *testing.T) {
	valid := testRecord("devbox", "devbox")
	tests := []Record{
		{Version: 2, Name: valid.Name, Host: valid.Host, Fingerprint: valid.Fingerprint},
		{Version: Version, Name: "../escape", Host: valid.Host, Fingerprint: valid.Fingerprint},
		{Version: Version, Name: "UPPER", Host: valid.Host, Fingerprint: valid.Fingerprint},
		{Version: Version, Name: "list", Host: valid.Host, Fingerprint: valid.Fingerprint},
		{Version: Version, Name: valid.Name, Host: "-oProxyCommand=evil", Fingerprint: valid.Fingerprint},
		{Version: Version, Name: valid.Name, Host: "space host", Fingerprint: valid.Fingerprint},
		{Version: Version, Name: valid.Name, Host: strings.Repeat("a", 4097), Fingerprint: valid.Fingerprint},
		{Version: Version, Name: valid.Name, Host: string([]byte{0xff}), Fingerprint: valid.Fingerprint},
		{Version: Version, Name: valid.Name, Host: valid.Host, Fingerprint: strings.ToUpper(valid.Fingerprint)},
	}
	for _, record := range tests {
		if err := ValidateRecord(record); err == nil {
			t.Errorf("ValidateRecord(%+v) succeeded", record)
		}
	}
}

func TestRegistryStaysAnchoredWhenStorePathIsRetargeted(t *testing.T) {
	first := newRegistryFixture(t)
	second := newRegistryFixture(t)
	firstRecord := testRecord("devbox", "first.example")
	secondRecord := testRecord("devbox", "second.example")
	if err := first.registry.Add(firstRecord); err != nil {
		t.Fatal(err)
	}
	if err := second.registry.Add(secondRecord); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(t.TempDir(), "store")
	if err := os.Symlink(first.directory, link); err != nil {
		t.Fatal(err)
	}
	opened, err := store.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	firstResolved, err := filepath.EvalSymlinks(first.directory)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Dir != firstResolved || opened.PasswordsDir != filepath.Join(firstResolved, "passwords") || opened.IdentitiesPath != filepath.Join(firstResolved, "identities") {
		t.Fatalf("Store.Open() retained retargetable paths: %+v", opened)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second.directory, link); err != nil {
		t.Fatal(err)
	}

	registry, err := Open(opened)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	actual, err := registry.Get("devbox")
	if err != nil {
		t.Fatal(err)
	}
	if actual != firstRecord {
		t.Fatalf("retargeted store registry = %+v, want %+v", actual, firstRecord)
	}
}

func TestStrictDecodeRejectsMalformedRecords(t *testing.T) {
	fixture := newRegistryFixture(t)
	if err := os.Mkdir(filepath.Join(fixture.directory, "peers"), 0o700); err != nil {
		t.Fatal(err)
	}
	valid := `{"version":1,"name":"devbox","host":"devbox","fingerprint":"` + testFingerprint + `"}`
	tests := []string{
		`{"version":1,"version":1,"name":"devbox","host":"devbox","fingerprint":"` + testFingerprint + `"}`,
		`{"version":1,"name":"devbox","host":"devbox","fingerprint":"` + testFingerprint + `","extra":true}`,
		valid + ` {}`,
		`[]`,
	}
	for index, data := range tests {
		path := filepath.Join(fixture.directory, "peers", "devbox.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.registry.Get("devbox"); err == nil {
			t.Errorf("malformed record %d was accepted", index)
		}
	}
}

func TestStrictDecodeRejectsInvalidUnicodeEncoding(t *testing.T) {
	fixture := newRegistryFixture(t)
	if err := os.Mkdir(filepath.Join(fixture.directory, "peers"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"invalid UTF-8":    append([]byte(`{"version":1,"name":"devbox","host":"`), append([]byte{0xff}, []byte(`","fingerprint":"`+testFingerprint+`"}`)...)...),
		"surrogate escape": []byte(`{"version":1,"name":"devbox","host":"\ud800","fingerprint":"` + testFingerprint + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(fixture.directory, "peers", "devbox.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.registry.Get("devbox"); err == nil {
				t.Fatal("Get() accepted invalid Unicode encoding")
			}
		})
	}
}

func TestRegistryRejectsUnsafeFilesystemEntries(t *testing.T) {
	t.Run("directory symlink", func(t *testing.T) {
		fixture := newRegistryFixture(t)
		if err := os.Symlink(t.TempDir(), filepath.Join(fixture.directory, "peers")); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.registry.List(); err == nil {
			t.Fatal("List() accepted symlink peers directory")
		}
	})
	t.Run("record symlink", func(t *testing.T) {
		fixture := newRegistryFixture(t)
		if err := os.Mkdir(filepath.Join(fixture.directory, "peers"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(fixture.directory, "recipients"), filepath.Join(fixture.directory, "peers", "devbox.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.registry.Get("devbox"); err == nil {
			t.Fatal("Get() accepted symlink record")
		}
	})
	t.Run("broad permissions", func(t *testing.T) {
		fixture := newRegistryFixture(t)
		if err := os.Mkdir(filepath.Join(fixture.directory, "peers"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.registry.List(); err == nil {
			t.Fatal("List() accepted broad peers directory permissions")
		}
	})
}

func TestConcurrentAddHasOneWinner(t *testing.T) {
	fixture := newRegistryFixture(t)
	records := []Record{testRecord("devbox", "one.example"), testRecord("devbox", "two.example")}
	errorsByIndex := make([]error, len(records))
	var wait sync.WaitGroup
	for index := range records {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsByIndex[index] = fixture.registry.Add(records[index])
		}(index)
	}
	wait.Wait()
	successes := 0
	for _, err := range errorsByIndex {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent Add() successes = %d, errors = %v", successes, errorsByIndex)
	}
	actual, err := fixture.registry.Get("devbox")
	if err != nil {
		t.Fatal(err)
	}
	if actual != records[0] && actual != records[1] {
		t.Fatalf("concurrent Add() produced unexpected record %+v", actual)
	}
}
