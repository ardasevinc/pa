package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/ardasevinc/pa/internal/transfer"
)

type Client struct {
	Host       string
	SSHPath    string
	SSHOptions []string
}

type Peer struct {
	Recipients  []byte `json:"-"`
	Fingerprint string `json:"fingerprint"`
}

type RemoteAppliedError struct {
	Result transfer.ImportResult
	Err    error
}

func (e *RemoteAppliedError) Error() string {
	return fmt.Sprintf("remote entries were applied but finalization failed: %v", e.Err)
}

func (e *RemoteAppliedError) Unwrap() error { return e.Err }

func (c Client) Recipient(ctx context.Context) (Peer, error) {
	session, err := c.start(ctx)
	if err != nil {
		return Peer{}, err
	}
	if err := writeRequest(session.stdin, commandRecipient); err != nil {
		return Peer{}, session.abort(err)
	}
	if err := session.stdin.Close(); err != nil {
		return Peer{}, session.abort(err)
	}
	status, err := readStatus(session.stdout)
	if err != nil {
		return Peer{}, session.abort(err)
	}
	if status != statusOK {
		return Peer{}, session.finish(readRemoteError(session.stdout, status))
	}
	recipients, err := readBytes32(session.stdout, maxRecipientBytes)
	if err != nil {
		return Peer{}, session.abort(err)
	}
	if err := session.finish(nil); err != nil {
		return Peer{}, err
	}
	digest := sha256.Sum256(recipients)
	return Peer{Recipients: recipients, Fingerprint: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

func (c Client) Push(ctx context.Context, bundlePath string) (transfer.ImportResult, error) {
	bundle, err := os.Open(bundlePath)
	if err != nil {
		return transfer.ImportResult{}, err
	}
	defer bundle.Close()
	info, err := bundle.Stat()
	if err != nil {
		return transfer.ImportResult{}, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) > maxBundleBytes {
		return transfer.ImportResult{}, errors.New("invalid encrypted bundle")
	}

	session, err := c.start(ctx)
	if err != nil {
		return transfer.ImportResult{}, err
	}
	if err := writeRequest(session.stdin, commandPush); err == nil {
		err = binary.Write(session.stdin, binary.BigEndian, uint64(info.Size()))
	}
	if err == nil {
		_, err = io.Copy(session.stdin, bundle)
	}
	if closeErr := session.stdin.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return transfer.ImportResult{}, session.abort(err)
	}

	status, err := readStatus(session.stdout)
	if err != nil {
		return transfer.ImportResult{}, session.abort(err)
	}
	payload, err := readBytes32(session.stdout, maxMessageBytes)
	if err != nil {
		return transfer.ImportResult{}, session.abort(err)
	}
	var envelope importEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return transfer.ImportResult{}, session.abort(err)
	}
	remoteErr := errorFromEnvelope(status, envelope)
	return envelope.Result, session.finish(remoteErr)
}

func (c Client) Pull(ctx context.Context, recipients []byte, outputPath string) error {
	if len(recipients) == 0 || len(recipients) > maxRecipientBytes {
		return errors.New("invalid local recipient file")
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return fmt.Errorf("pull output already exists: %s", outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	session, err := c.start(ctx)
	if err != nil {
		return err
	}
	if err := writeRequest(session.stdin, commandPull); err == nil {
		err = writeBytes32(session.stdin, recipients)
	}
	if closeErr := session.stdin.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return session.abort(err)
	}
	status, err := readStatus(session.stdout)
	if err != nil {
		return session.abort(err)
	}
	if status != statusOK {
		return session.finish(readRemoteError(session.stdout, status))
	}
	var length uint64
	if err := binary.Read(session.stdout, binary.BigEndian, &length); err != nil {
		return session.abort(err)
	}
	if length > maxBundleBytes {
		return session.abort(errors.New("remote encrypted bundle exceeds transfer limit"))
	}
	temporary, err := os.CreateTemp(filepath.Dir(outputPath), ".pa-pull-*.age")
	if err != nil {
		return session.abort(err)
	}
	temporaryPath := temporary.Name()
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err == nil {
		_, err = io.CopyN(temporary, session.stdout, int64(length))
	}
	if syncErr := temporary.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return session.abort(err)
	}
	if err := session.finish(nil); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, outputPath); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(outputPath)); err != nil {
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	complete = true
	return nil
}

type sshSession struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  *boundedBuffer
}

func (c Client) start(ctx context.Context) (*sshSession, error) {
	if err := ValidateHost(c.Host); err != nil {
		return nil, err
	}
	if err := ValidateSSHOptions(c.SSHOptions); err != nil {
		return nil, err
	}
	sshPath := c.SSHPath
	if sshPath == "" {
		sshPath = "ssh"
	}
	path, err := exec.LookPath(sshPath)
	if err != nil {
		return nil, fmt.Errorf("find ssh: %w", err)
	}
	// OpenSSH generally keeps the first value obtained for a setting, so these
	// enforced values must precede user connection options.
	arguments := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"}
	arguments = append(arguments, c.SSHOptions...)
	arguments = append(arguments, c.Host, "pa-xfer serve")
	command := exec.CommandContext(ctx, path, arguments...)
	stderr := &boundedBuffer{limit: 64 * 1024}
	command.Stderr = stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	return &sshSession{command: command, stdin: stdin, stdout: stdout, stderr: stderr}, nil
}

func (s *sshSession) finish(operationErr error) error {
	_ = s.stdout.Close()
	waitErr := s.command.Wait()
	if waitErr != nil {
		waitErr = fmt.Errorf("ssh failed: %w%s", waitErr, formatStderr(s.stderr.String()))
	}
	return errors.Join(operationErr, waitErr)
}

func (s *sshSession) abort(operationErr error) error {
	_ = s.stdin.Close()
	_ = s.stdout.Close()
	if s.command.Process != nil {
		_ = s.command.Process.Kill()
	}
	waitErr := s.command.Wait()
	if waitErr != nil {
		waitErr = fmt.Errorf("ssh failed: %w%s", waitErr, formatStderr(s.stderr.String()))
	}
	return errors.Join(operationErr, waitErr)
}

func readStatus(input io.Reader) (byte, error) {
	var status [1]byte
	_, err := io.ReadFull(input, status[:])
	return status[0], err
}

func readRemoteError(input io.Reader, status byte) error {
	message, err := readBytes32(input, maxMessageBytes)
	if err != nil {
		return err
	}
	return fmt.Errorf("remote error (status %d): %s", status, message)
}

func errorFromEnvelope(status byte, envelope importEnvelope) error {
	if status == statusOK {
		return nil
	}
	err := errors.New(envelope.Error)
	if status == statusApplied {
		return &RemoteAppliedError{Result: envelope.Result, Err: err}
	}
	return fmt.Errorf("remote import failed: %w", err)
}

func ValidateHost(host string) error {
	if host == "" || strings.HasPrefix(host, "-") {
		return errors.New("invalid SSH host")
	}
	for _, character := range host {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return errors.New("SSH host cannot contain whitespace or control characters")
		}
	}
	return nil
}

func ValidateSSHOptions(options []string) error {
	valueOptions := "BbCcDEeFIiJLlmOoPpQRSwW"
	flagOptions := "46AaCfGgKkMNnqTtVvXxYy"
	for index := 0; index < len(options); index++ {
		option := options[index]
		if len(option) < 2 || option[0] != '-' || option == "--" {
			return fmt.Errorf("invalid SSH option %q: positional arguments are not allowed", option)
		}
		name := option[1]
		if strings.ContainsRune(flagOptions, rune(name)) {
			continue
		}
		if !strings.ContainsRune(valueOptions, rune(name)) {
			return fmt.Errorf("unsupported SSH option %q", option)
		}
		if len(option) > 2 {
			continue
		}
		index++
		if index >= len(options) || options[index] == "" {
			return fmt.Errorf("SSH option %q requires a value", option)
		}
	}
	return nil
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	length := len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.buffer.Write(data)
	}
	return length, nil
}

func (b *boundedBuffer) String() string { return b.buffer.String() }

func formatStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
