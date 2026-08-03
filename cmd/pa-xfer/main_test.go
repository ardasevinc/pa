package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(help) = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pa-xfer export") {
		t.Fatalf("help output = %q", stdout.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"explode"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(unknown) = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunRecipientJSON(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "passwords"), 0o700); err != nil {
		t.Fatal(err)
	}
	recipients := []byte("age1example\n")
	if err := os.WriteFile(filepath.Join(directory, "recipients"), recipients, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "identities"), []byte("identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"recipient", "--json", "--store", directory}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(recipient) = %d, stderr = %q", code, stderr.String())
	}
	digest := sha256.Sum256(recipients)
	wantFingerprint := "sha256:" + hex.EncodeToString(digest[:])
	if !strings.Contains(stdout.String(), wantFingerprint) || !strings.Contains(stdout.String(), "age1example") {
		t.Fatalf("recipient output = %q", stdout.String())
	}
}

func TestDefaultStoreDir(t *testing.T) {
	t.Setenv("PA_DIR", "/explicit")
	t.Setenv("XDG_DATA_HOME", "/xdg")
	if actual := defaultStoreDir(); actual != "/explicit" {
		t.Fatalf("defaultStoreDir() = %q", actual)
	}
	t.Setenv("PA_DIR", "")
	if actual := defaultStoreDir(); actual != "/xdg/pa" {
		t.Fatalf("defaultStoreDir() = %q", actual)
	}
}
