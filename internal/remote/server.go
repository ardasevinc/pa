package remote

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/store"
	"github.com/ardasevinc/pa/internal/transfer"
)

type importEnvelope struct {
	Result transfer.ImportResult `json:"result"`
	Error  string                `json:"error,omitempty"`
}

// Serve handles one request. It writes only the binary protocol to output.
func Serve(ctx context.Context, age agecmd.Tool, storeDirectory string, input io.Reader, output io.Writer) error {
	command, err := readRequest(input)
	if err != nil {
		return fmt.Errorf("read pa SSH request: %w", err)
	}
	switch command {
	case commandRecipient:
		return serveRecipient(storeDirectory, output)
	case commandPush:
		return servePush(ctx, age, storeDirectory, input, output)
	case commandPull:
		return servePull(ctx, age, storeDirectory, input, output)
	default:
		return fmt.Errorf("unknown pa SSH command %d", command)
	}
}

func serveRecipient(storeDirectory string, output io.Writer) error {
	opened, err := store.Open(storeDirectory)
	if err != nil {
		return writeError(output, err)
	}
	path := opened.RecipientsPath
	if err := opened.Close(); err != nil {
		return writeError(output, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return writeError(output, err)
	}
	if len(data) > maxRecipientBytes {
		return writeError(output, errors.New("recipient file is too large"))
	}
	if err := writeAll(output, []byte{statusOK}); err != nil {
		return err
	}
	return writeBytes32(output, data)
}

func servePush(ctx context.Context, age agecmd.Tool, storeDirectory string, input io.Reader, output io.Writer) error {
	var length uint64
	if err := binary.Read(input, binary.BigEndian, &length); err != nil {
		return err
	}
	if length > maxBundleBytes {
		return writeError(output, fmt.Errorf("encrypted bundle is too large: %d bytes", length))
	}
	bundlePath, cleanup, err := receiveEncryptedFile(storeDirectory, "push", input, length)
	if err != nil {
		return writeError(output, err)
	}
	defer cleanup()

	opened, err := store.Open(storeDirectory)
	if err != nil {
		return writeError(output, err)
	}
	result, importErr := transfer.Import(ctx, age, opened, bundlePath)
	closeErr := opened.Close()
	importErr = errors.Join(importErr, closeErr)

	status := statusOK
	if importErr != nil {
		var applied *transfer.AppliedError
		if errors.As(importErr, &applied) {
			status = statusApplied
		} else {
			status = statusError
		}
	}
	payload, err := json.Marshal(importEnvelope{Result: result, Error: errorString(importErr)})
	if err != nil {
		return writeError(output, err)
	}
	if err := writeAll(output, []byte{status}); err != nil {
		return err
	}
	return writeBytes32(output, payload)
}

func servePull(ctx context.Context, age agecmd.Tool, storeDirectory string, input io.Reader, output io.Writer) error {
	recipients, err := readBytes32(input, maxRecipientBytes)
	if err != nil {
		return err
	}
	temporaryDirectory, err := ensureTemporaryDirectory(storeDirectory)
	if err != nil {
		return writeError(output, err)
	}
	recipientsFile, err := os.CreateTemp(temporaryDirectory, ".pa-pull-recipients-*")
	if err != nil {
		return writeError(output, err)
	}
	recipientsPath := recipientsFile.Name()
	defer os.Remove(recipientsPath)
	if err := errors.Join(recipientsFile.Chmod(0o600), writeFile(recipientsFile, recipients), recipientsFile.Close()); err != nil {
		return writeError(output, err)
	}
	bundleFile, err := os.CreateTemp(temporaryDirectory, ".pa-pull-bundle-*.age")
	if err != nil {
		return writeError(output, err)
	}
	bundlePath := bundleFile.Name()
	if err := bundleFile.Close(); err != nil {
		_ = os.Remove(bundlePath)
		return writeError(output, err)
	}
	if err := os.Remove(bundlePath); err != nil {
		return writeError(output, err)
	}
	defer os.Remove(bundlePath)

	opened, err := store.Open(storeDirectory)
	if err != nil {
		return writeError(output, err)
	}
	_, exportErr := transfer.Export(ctx, age, opened, recipientsPath, bundlePath)
	closeErr := opened.Close()
	if err := errors.Join(exportErr, closeErr); err != nil {
		return writeError(output, err)
	}
	bundle, err := os.Open(bundlePath)
	if err != nil {
		return writeError(output, err)
	}
	defer bundle.Close()
	info, err := bundle.Stat()
	if err != nil {
		return writeError(output, err)
	}
	if info.Size() < 0 || uint64(info.Size()) > maxBundleBytes {
		return writeError(output, errors.New("encrypted bundle exceeds transfer limit"))
	}
	if err := writeAll(output, []byte{statusOK}); err != nil {
		return err
	}
	if err := binary.Write(output, binary.BigEndian, uint64(info.Size())); err != nil {
		return err
	}
	_, err = io.Copy(output, bundle)
	return err
}

func receiveEncryptedFile(storeDirectory, label string, input io.Reader, length uint64) (string, func(), error) {
	directory, err := ensureTemporaryDirectory(storeDirectory)
	if err != nil {
		return "", func() {}, err
	}
	file, err := os.CreateTemp(directory, ".pa-"+label+"-*.age")
	if err != nil {
		return "", func() {}, err
	}
	name := file.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	written, copyErr := io.CopyN(file, input, int64(length))
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if uint64(written) != length {
		cleanup()
		return "", func() {}, io.ErrUnexpectedEOF
	}
	return name, cleanup, nil
}

func ensureTemporaryDirectory(storeDirectory string) (string, error) {
	directory := filepath.Join(storeDirectory, "transactions")
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return "", err
		}
		return directory, nil
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("pa transactions path is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("pa transactions directory is accessible by other users")
	}
	return directory, nil
}

func writeError(output io.Writer, err error) error {
	if writeErr := writeAll(output, []byte{statusError}); writeErr != nil {
		return writeErr
	}
	return writeBytes32(output, []byte(err.Error()))
}

func writeFile(file *os.File, data []byte) error {
	if err := writeAll(file, data); err != nil {
		return err
	}
	return file.Sync()
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
