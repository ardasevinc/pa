package agecmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

const maxErrorBytes = 64 * 1024

type Tool struct {
	Path string
}

func Find(explicitPath string) (Tool, error) {
	if explicitPath != "" {
		path, err := exec.LookPath(explicitPath)
		if err != nil {
			return Tool{}, fmt.Errorf("find age command %q: %w", explicitPath, err)
		}
		return Tool{Path: path}, nil
	}

	for _, candidate := range []string{"age", "rage"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return Tool{Path: path}, nil
		}
	}
	return Tool{}, errors.New("age not found, install it from https://age-encryption.org")
}

func (t Tool) StartEncrypt(ctx context.Context, recipientsPath, outputPath string) (*EncryptWriter, error) {
	command := exec.CommandContext(ctx, t.Path, "--encrypt", "-R", recipientsPath, "-o", outputPath)
	stderr := &limitedBuffer{limit: maxErrorBytes}
	command.Stderr = stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open age encryption input: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start age encryption: %w", err)
	}
	return &EncryptWriter{stdin: stdin, command: command, stderr: stderr}, nil
}

func (t Tool) StartDecrypt(ctx context.Context, identitiesPath, inputPath string) (*DecryptReader, error) {
	command := exec.CommandContext(ctx, t.Path, "--decrypt", "-i", identitiesPath, inputPath)
	stderr := &limitedBuffer{limit: maxErrorBytes}
	command.Stderr = stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open age decryption output: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = stdout.Close()
		return nil, fmt.Errorf("start age decryption: %w", err)
	}
	return &DecryptReader{stdout: stdout, command: command, stderr: stderr}, nil
}

type EncryptWriter struct {
	stdin   io.WriteCloser
	command *exec.Cmd
	stderr  *limitedBuffer
	waited  bool
}

func (w *EncryptWriter) Write(data []byte) (int, error) {
	return w.stdin.Write(data)
}

func (w *EncryptWriter) Close() error {
	closeErr := w.stdin.Close()
	waitErr := w.wait()
	return errors.Join(closeErr, waitErr)
}

func (w *EncryptWriter) Abort() error {
	_ = w.stdin.Close()
	if w.command.Process != nil {
		_ = w.command.Process.Kill()
	}
	return w.wait()
}

func (w *EncryptWriter) wait() error {
	if w.waited {
		return nil
	}
	w.waited = true
	if err := w.command.Wait(); err != nil {
		return commandError("age encryption", err, w.stderr.String())
	}
	return nil
}

type DecryptReader struct {
	stdout  io.ReadCloser
	command *exec.Cmd
	stderr  *limitedBuffer
	waited  bool
}

func (r *DecryptReader) Read(data []byte) (int, error) {
	return r.stdout.Read(data)
}

func (r *DecryptReader) Close() error {
	closeErr := r.stdout.Close()
	waitErr := r.wait()
	return errors.Join(closeErr, waitErr)
}

func (r *DecryptReader) Abort() error {
	_ = r.stdout.Close()
	if r.command.Process != nil {
		_ = r.command.Process.Kill()
	}
	return r.wait()
}

func (r *DecryptReader) wait() error {
	if r.waited {
		return nil
	}
	r.waited = true
	if err := r.command.Wait(); err != nil {
		return commandError("age decryption", err, r.stderr.String())
	}
	return nil
}

func commandError(operation string, err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return fmt.Errorf("%s failed: %w", operation, err)
	}
	return fmt.Errorf("%s failed: %w: %s", operation, err, stderr)
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
			b.truncated = true
		}
		_, _ = b.buffer.Write(data)
	} else if originalLength > 0 {
		b.truncated = true
	}
	return originalLength, nil
}

func (b *limitedBuffer) String() string {
	if b.truncated {
		return b.buffer.String() + " [truncated]"
	}
	return b.buffer.String()
}
