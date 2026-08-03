package transfer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/ardasevinc/pa/internal/agecmd"
	"github.com/ardasevinc/pa/internal/protocol"
)

type VerifyResult struct {
	Entries uint32 `json:"entries"`
	Bytes   uint64 `json:"bytes"`
}

type verifyConsumer struct{}

func (verifyConsumer) BeginEntry(string) (io.Writer, error) {
	return io.Discard, nil
}

func (verifyConsumer) EndEntry(string, uint64, [sha256.Size]byte) error {
	return nil
}

// Verify authenticates and fully decodes a bundle without writing password data.
func Verify(ctx context.Context, age agecmd.Tool, identitiesPath, bundlePath string) (VerifyResult, error) {
	if err := requireRegularFile(bundlePath); err != nil {
		return VerifyResult{}, fmt.Errorf("inspect encrypted bundle: %w", err)
	}
	if err := requireRegularFile(identitiesPath); err != nil {
		return VerifyResult{}, fmt.Errorf("inspect identities: %w", err)
	}

	decrypted, err := age.StartDecrypt(ctx, identitiesPath, bundlePath)
	if err != nil {
		return VerifyResult{}, err
	}
	stats, decodeErr := protocol.Decode(decrypted, verifyConsumer{})
	if decodeErr != nil {
		_ = decrypted.Abort()
		return VerifyResult{}, fmt.Errorf("decode encrypted bundle: %w", decodeErr)
	}
	if err := decrypted.Close(); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Entries: stats.Entries, Bytes: stats.Bytes}, nil
}
