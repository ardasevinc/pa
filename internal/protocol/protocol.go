package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	frameEntryStart byte = 0x01
	frameEntryData  byte = 0x02
	frameEntryEnd   byte = 0x03
	frameBundleEnd  byte = 0xff

	MaxNameBytes  = 4 * 1024
	MaxChunkBytes = 64 * 1024
	MaxEntries    = 1_000_000
	MaxValueBytes = 1 << 40 // 1 TiB safety bound; data is still streamed.
)

var magic = [8]byte{'P', 'A', 'X', 'F', 'E', 'R', '1', '\n'}

var (
	ErrClosed          = errors.New("protocol encoder is closed")
	ErrDuplicateName   = errors.New("duplicate entry name")
	ErrInvalidName     = errors.New("invalid entry name")
	ErrMalformedBundle = errors.New("malformed transfer bundle")
	ErrLimitExceeded   = errors.New("transfer limit exceeded")
)

type Stats struct {
	Entries uint32
	Bytes   uint64
}

type Consumer interface {
	BeginEntry(name string) (io.Writer, error)
	EndEntry(name string, size uint64, digest [sha256.Size]byte) error
}

type Encoder struct {
	raw        io.Writer
	w          io.Writer
	transcript hash.Hash
	seen       map[string]struct{}
	stats      Stats
	closed     bool
}

func NewEncoder(w io.Writer) (*Encoder, error) {
	transcript := sha256.New()
	encoder := &Encoder{
		raw:        w,
		w:          io.MultiWriter(w, transcript),
		transcript: transcript,
		seen:       make(map[string]struct{}),
	}

	if _, err := encoder.w.Write(magic[:]); err != nil {
		return nil, fmt.Errorf("write protocol magic: %w", err)
	}

	return encoder, nil
}

func (e *Encoder) Add(name string, value io.Reader) error {
	if e.closed {
		return ErrClosed
	}
	if e.stats.Entries >= MaxEntries {
		return fmt.Errorf("%w: too many entries", ErrLimitExceeded)
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	if _, ok := e.seen[name]; ok {
		return fmt.Errorf("%w: %q", ErrDuplicateName, name)
	}
	e.seen[name] = struct{}{}

	if err := writeByte(e.w, frameEntryStart); err != nil {
		return err
	}
	if err := binary.Write(e.w, binary.BigEndian, uint32(len(name))); err != nil {
		return fmt.Errorf("write name length: %w", err)
	}
	if _, err := io.WriteString(e.w, name); err != nil {
		return fmt.Errorf("write entry name: %w", err)
	}

	digest := sha256.New()
	buffer := make([]byte, MaxChunkBytes)
	var size uint64
	for {
		n, readErr := value.Read(buffer)
		if n > 0 {
			if size > MaxValueBytes-uint64(n) {
				return fmt.Errorf("%w: value for %q", ErrLimitExceeded, name)
			}
			size += uint64(n)

			if err := writeByte(e.w, frameEntryData); err != nil {
				return err
			}
			if err := binary.Write(e.w, binary.BigEndian, uint32(n)); err != nil {
				return fmt.Errorf("write chunk length: %w", err)
			}
			if _, err := e.w.Write(buffer[:n]); err != nil {
				return fmt.Errorf("write value chunk: %w", err)
			}
			if _, err := digest.Write(buffer[:n]); err != nil {
				return fmt.Errorf("hash value chunk: %w", err)
			}
		}

		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return fmt.Errorf("read value for %q: %w", name, readErr)
			}
			break
		}
	}

	if err := writeByte(e.w, frameEntryEnd); err != nil {
		return err
	}
	if err := binary.Write(e.w, binary.BigEndian, size); err != nil {
		return fmt.Errorf("write value length: %w", err)
	}
	if _, err := e.w.Write(digest.Sum(nil)); err != nil {
		return fmt.Errorf("write value digest: %w", err)
	}

	e.stats.Entries++
	e.stats.Bytes += size
	return nil
}

func (e *Encoder) Close() (Stats, error) {
	if e.closed {
		return e.stats, ErrClosed
	}
	e.closed = true

	if err := writeByte(e.w, frameBundleEnd); err != nil {
		return e.stats, err
	}
	if err := binary.Write(e.w, binary.BigEndian, e.stats.Entries); err != nil {
		return e.stats, fmt.Errorf("write entry count: %w", err)
	}

	digest := e.transcript.Sum(nil)
	if _, err := e.raw.Write(digest); err != nil {
		return e.stats, fmt.Errorf("write transcript digest: %w", err)
	}

	return e.stats, nil
}

func Decode(r io.Reader, consumer Consumer) (Stats, error) {
	transcript := sha256.New()
	hashedReader := io.TeeReader(r, transcript)

	var receivedMagic [len(magic)]byte
	if _, err := io.ReadFull(hashedReader, receivedMagic[:]); err != nil {
		return Stats{}, malformed("read protocol magic", err)
	}
	if receivedMagic != magic {
		return Stats{}, malformed("invalid protocol magic", nil)
	}

	seen := make(map[string]struct{})
	stats := Stats{}
	var (
		currentName   string
		currentWriter io.Writer
		currentDigest hash.Hash
		currentSize   uint64
	)

	for {
		frameType, err := readByte(hashedReader)
		if err != nil {
			return stats, malformed("read frame type", err)
		}

		switch frameType {
		case frameEntryStart:
			if currentName != "" {
				return stats, malformed("entry started before previous entry ended", nil)
			}
			if stats.Entries >= MaxEntries {
				return stats, fmt.Errorf("%w: too many entries", ErrLimitExceeded)
			}

			var nameLength uint32
			if err := binary.Read(hashedReader, binary.BigEndian, &nameLength); err != nil {
				return stats, malformed("read name length", err)
			}
			if nameLength == 0 || nameLength > MaxNameBytes {
				return stats, fmt.Errorf("%w: invalid name length %d", ErrLimitExceeded, nameLength)
			}

			nameBytes := make([]byte, nameLength)
			if _, err := io.ReadFull(hashedReader, nameBytes); err != nil {
				return stats, malformed("read entry name", err)
			}
			currentName = string(nameBytes)
			if err := ValidateName(currentName); err != nil {
				return stats, err
			}
			if _, ok := seen[currentName]; ok {
				return stats, fmt.Errorf("%w: %q", ErrDuplicateName, currentName)
			}
			seen[currentName] = struct{}{}

			currentWriter = io.Discard
			if consumer != nil {
				currentWriter, err = consumer.BeginEntry(currentName)
				if err != nil {
					return stats, fmt.Errorf("begin entry %q: %w", currentName, err)
				}
				if currentWriter == nil {
					currentWriter = io.Discard
				}
			}
			currentDigest = sha256.New()
			currentSize = 0

		case frameEntryData:
			if currentName == "" {
				return stats, malformed("data frame outside an entry", nil)
			}

			var chunkLength uint32
			if err := binary.Read(hashedReader, binary.BigEndian, &chunkLength); err != nil {
				return stats, malformed("read chunk length", err)
			}
			if chunkLength == 0 || chunkLength > MaxChunkBytes {
				return stats, fmt.Errorf("%w: invalid chunk length %d", ErrLimitExceeded, chunkLength)
			}
			if currentSize > MaxValueBytes-uint64(chunkLength) {
				return stats, fmt.Errorf("%w: value for %q", ErrLimitExceeded, currentName)
			}

			writer := io.MultiWriter(currentWriter, currentDigest)
			written, err := io.CopyN(writer, hashedReader, int64(chunkLength))
			if err != nil {
				return stats, malformed("read value chunk", err)
			}
			if written != int64(chunkLength) {
				return stats, malformed("short value chunk", nil)
			}
			currentSize += uint64(chunkLength)

		case frameEntryEnd:
			if currentName == "" {
				return stats, malformed("entry end outside an entry", nil)
			}

			var expectedSize uint64
			if err := binary.Read(hashedReader, binary.BigEndian, &expectedSize); err != nil {
				return stats, malformed("read value length", err)
			}
			var expectedDigest [sha256.Size]byte
			if _, err := io.ReadFull(hashedReader, expectedDigest[:]); err != nil {
				return stats, malformed("read value digest", err)
			}
			if currentSize != expectedSize {
				return stats, malformed("value length mismatch", nil)
			}
			if !equalDigest(currentDigest.Sum(nil), expectedDigest) {
				return stats, malformed("value digest mismatch", nil)
			}

			if consumer != nil {
				if err := consumer.EndEntry(currentName, currentSize, expectedDigest); err != nil {
					return stats, fmt.Errorf("end entry %q: %w", currentName, err)
				}
			}

			stats.Entries++
			stats.Bytes += currentSize
			currentName = ""
			currentWriter = nil
			currentDigest = nil
			currentSize = 0

		case frameBundleEnd:
			if currentName != "" {
				return stats, malformed("bundle ended inside an entry", nil)
			}

			var expectedEntries uint32
			if err := binary.Read(hashedReader, binary.BigEndian, &expectedEntries); err != nil {
				return stats, malformed("read final entry count", err)
			}
			actualTranscript := transcript.Sum(nil)

			var expectedTranscript [sha256.Size]byte
			if _, err := io.ReadFull(r, expectedTranscript[:]); err != nil {
				return stats, malformed("read transcript digest", err)
			}
			if stats.Entries != expectedEntries {
				return stats, malformed("entry count mismatch", nil)
			}
			if !equalDigest(actualTranscript, expectedTranscript) {
				return stats, malformed("transcript digest mismatch", nil)
			}

			var trailing [1]byte
			if _, err := io.ReadFull(r, trailing[:]); err == nil {
				return stats, malformed("trailing bytes after bundle end", nil)
			} else if !errors.Is(err, io.EOF) {
				return stats, malformed("read after bundle end", err)
			}

			return stats, nil

		default:
			return stats, malformed(fmt.Sprintf("unknown frame type 0x%02x", frameType), nil)
		}
	}
}

func ValidateName(name string) error {
	if name == "" || len(name) > MaxNameBytes || !utf8.ValidString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || path.Clean(name) != name {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}

	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." ||
			component == ".git" || strings.HasPrefix(component, ".pa-") {
			return fmt.Errorf("%w: reserved component in %q", ErrInvalidName, name)
		}
		for _, character := range component {
			if unicode.IsControl(character) {
				return fmt.Errorf("%w: control character in %q", ErrInvalidName, name)
			}
		}
	}

	return nil
}

func writeByte(w io.Writer, value byte) error {
	if _, err := w.Write([]byte{value}); err != nil {
		return fmt.Errorf("write frame type: %w", err)
	}
	return nil
}

func readByte(r io.Reader) (byte, error) {
	var value [1]byte
	_, err := io.ReadFull(r, value[:])
	return value[0], err
}

func malformed(message string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrMalformedBundle, message)
	}
	return fmt.Errorf("%w: %s: %v", ErrMalformedBundle, message, err)
}

func equalDigest(actual []byte, expected [sha256.Size]byte) bool {
	return bytes.Equal(actual, expected[:])
}
