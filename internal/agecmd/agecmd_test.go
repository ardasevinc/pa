package agecmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptExactBytes(t *testing.T) {
	tool, err := Find("")
	if err != nil {
		t.Skip(err)
	}
	directory := t.TempDir()
	identities, recipients := generateIdentity(t, directory, "identity")
	output := filepath.Join(directory, "secret.age")
	value := []byte{'a', 0x00, 0xff, '\n', '\n'}

	writer, err := tool.StartEncrypt(context.Background(), recipients, output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := tool.StartDecrypt(context.Background(), identities, output)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("decrypt errors = %v, %v", readErr, closeErr)
	}
	if !bytes.Equal(actual, value) {
		t.Fatalf("decrypted value = %x, want %x", actual, value)
	}
}

func TestDecryptWrongIdentityFails(t *testing.T) {
	tool, err := Find("")
	if err != nil {
		t.Skip(err)
	}
	directory := t.TempDir()
	_, recipients := generateIdentity(t, directory, "source")
	wrongIdentity, _ := generateIdentity(t, directory, "wrong")
	output := filepath.Join(directory, "secret.age")

	writer, err := tool.StartEncrypt(context.Background(), recipients, output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := tool.StartDecrypt(context.Background(), wrongIdentity, output)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, reader)
	if err := reader.Close(); err == nil {
		t.Fatal("decryption with the wrong identity succeeded")
	}
}

func TestLimitedBuffer(t *testing.T) {
	buffer := &limitedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("abcdef")); err != nil || written != 6 {
		t.Fatalf("Write() = %d, %v", written, err)
	}
	if got := buffer.String(); got != "abcd [truncated]" {
		t.Fatalf("String() = %q", got)
	}
}

func generateIdentity(t *testing.T, directory, name string) (string, string) {
	t.Helper()
	keygen, err := exec.LookPath("age-keygen")
	if err != nil {
		keygen, err = exec.LookPath("rage-keygen")
	}
	if err != nil {
		t.Skip("age-keygen or rage-keygen not installed")
	}

	identities := filepath.Join(directory, name+".identities")
	recipients := filepath.Join(directory, name+".recipients")
	command := exec.Command(keygen, "-o", identities)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate identity: %v: %s", err, output)
	}
	command = exec.Command(keygen, "-y", "-o", recipients, identities)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate recipient: %v: %s", err, output)
	}
	if err := os.Chmod(identities, 0o600); err != nil {
		t.Fatal(err)
	}
	return identities, recipients
}
