package protocol

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

type collectedEntry struct {
	buffer *bytes.Buffer
	size   uint64
	digest [sha256.Size]byte
}

type collector struct {
	entries map[string]*collectedEntry
}

func newCollector() *collector {
	return &collector{entries: make(map[string]*collectedEntry)}
}

func (c *collector) BeginEntry(name string) (io.Writer, error) {
	entry := &collectedEntry{buffer: &bytes.Buffer{}}
	c.entries[name] = entry
	return entry.buffer, nil
}

func (c *collector) EndEntry(name string, size uint64, digest [sha256.Size]byte) error {
	entry, ok := c.entries[name]
	if !ok {
		return fmt.Errorf("entry %q was not started", name)
	}
	entry.size = size
	entry.digest = digest
	return nil
}

func encodeBundle(t *testing.T, entries []struct {
	name  string
	value []byte
}) []byte {
	t.Helper()

	var bundle bytes.Buffer
	encoder, err := NewEncoder(&bundle)
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	for _, entry := range entries {
		if err := encoder.Add(entry.name, bytes.NewReader(entry.value)); err != nil {
			t.Fatalf("Add(%q) error = %v", entry.name, err)
		}
	}
	if _, err := encoder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return bundle.Bytes()
}

func TestRoundTripExactBytes(t *testing.T) {
	large := make([]byte, MaxChunkBytes*2+17)
	for index := range large {
		large[index] = byte(index % 251)
	}

	entries := []struct {
		name  string
		value []byte
	}{
		{name: "empty", value: []byte{}},
		{name: "text/trailing-newlines", value: []byte("alpha\nbeta\n\n")},
		{name: "binary", value: []byte{0x00, 0xff, '\t', '\r', '\n', 0x00}},
		{name: "unicode/şifre", value: []byte("değer")},
		{name: "large", value: large},
	}

	bundle := encodeBundle(t, entries)
	consumer := newCollector()
	stats, err := Decode(bytes.NewReader(bundle), consumer)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if stats.Entries != uint32(len(entries)) {
		t.Fatalf("Entries = %d, want %d", stats.Entries, len(entries))
	}

	var expectedBytes uint64
	for _, expected := range entries {
		expectedBytes += uint64(len(expected.value))
		actual := consumer.entries[expected.name]
		if actual == nil {
			t.Fatalf("missing entry %q", expected.name)
		}
		if !bytes.Equal(actual.buffer.Bytes(), expected.value) {
			t.Errorf("value for %q was not preserved", expected.name)
		}
		if actual.size != uint64(len(expected.value)) {
			t.Errorf("size for %q = %d, want %d", expected.name, actual.size, len(expected.value))
		}
		if actual.digest != sha256.Sum256(expected.value) {
			t.Errorf("digest for %q did not match", expected.name)
		}
	}
	if stats.Bytes != expectedBytes {
		t.Errorf("Bytes = %d, want %d", stats.Bytes, expectedBytes)
	}
}

func TestDecodeRejectsEveryTruncation(t *testing.T) {
	bundle := encodeBundle(t, []struct {
		name  string
		value []byte
	}{{name: "one", value: []byte("secret")}})

	for length := range len(bundle) {
		_, err := Decode(bytes.NewReader(bundle[:length]), newCollector())
		if err == nil {
			t.Fatalf("Decode() accepted bundle truncated to %d bytes", length)
		}
	}
}

func TestDecodeRejectsTamperingAndTrailingBytes(t *testing.T) {
	bundle := encodeBundle(t, []struct {
		name  string
		value []byte
	}{{name: "one", value: []byte("unique-secret-value")}})

	tampered := append([]byte(nil), bundle...)
	position := bytes.Index(tampered, []byte("unique-secret-value"))
	if position < 0 {
		t.Fatal("encoded value not found")
	}
	tampered[position] ^= 0xff
	if _, err := Decode(bytes.NewReader(tampered), newCollector()); err == nil {
		t.Fatal("Decode() accepted tampered value")
	}

	trailing := append(append([]byte(nil), bundle...), 0x00)
	if _, err := Decode(bytes.NewReader(trailing), newCollector()); err == nil {
		t.Fatal("Decode() accepted trailing bytes")
	}
}

func TestDecodeRejectsDuplicateNames(t *testing.T) {
	bundle := encodeBundle(t, []struct {
		name  string
		value []byte
	}{
		{name: "one", value: []byte("first")},
		{name: "two", value: []byte("second")},
	})

	first := bytes.Index(bundle, []byte("one"))
	second := bytes.Index(bundle[first+3:], []byte("two"))
	if first < 0 || second < 0 {
		t.Fatal("entry names not found in encoded bundle")
	}
	second += first + 3
	copy(bundle[second:second+3], "one")

	_, err := Decode(bytes.NewReader(bundle), newCollector())
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("Decode() error = %v, want ErrDuplicateName", err)
	}
}

func TestDecodeRejectsUnknownFrame(t *testing.T) {
	bundle := encodeBundle(t, nil)
	bundle[len(magic)] = 0x7f

	_, err := Decode(bytes.NewReader(bundle), newCollector())
	if !errors.Is(err, ErrMalformedBundle) {
		t.Fatalf("Decode() error = %v, want ErrMalformedBundle", err)
	}
}

func TestEncoderLifecycle(t *testing.T) {
	var bundle bytes.Buffer
	encoder, err := NewEncoder(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := encoder.Add("same", strings.NewReader("first")); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Add("same", strings.NewReader("second")); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate Add() error = %v, want ErrDuplicateName", err)
	}
	if _, err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Add("later", strings.NewReader("value")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Add() after Close() error = %v, want ErrClosed", err)
	}
	if _, err := encoder.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("second Close() error = %v, want ErrClosed", err)
	}
}

func TestValidateName(t *testing.T) {
	valid := []string{
		"simple",
		"nested/password",
		"spaces are fine",
		"unicode/şifre",
		"leading-hyphen/-entry",
	}
	for _, name := range valid {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) error = %v", name, err)
		}
	}

	invalid := []string{
		"",
		"/absolute",
		"trailing/",
		"double//slash",
		".",
		"..",
		"nested/../escape",
		"nested/./entry",
		".git/config",
		"nested/.pa-stage/entry",
		"control\ncharacter",
		string([]byte{0xff}),
	}
	for _, name := range invalid {
		if err := ValidateName(name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("ValidateName(%q) error = %v, want ErrInvalidName", name, err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	var valid bytes.Buffer
	encoder, err := NewEncoder(&valid)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := encoder.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte("not-a-bundle"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Decode(bytes.NewReader(data), nil)
	})
}
