package remote

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	wireMagic         = "PAXSSH1\n"
	commandRecipient  = byte(1)
	commandPush       = byte(2)
	commandPull       = byte(3)
	statusOK          = byte(0)
	statusError       = byte(1)
	statusApplied     = byte(2)
	maxRecipientBytes = 1 << 20
	maxMessageBytes   = 1 << 20
	maxBundleBytes    = uint64(8) << 30
)

func writeRequest(output io.Writer, command byte) error {
	if _, err := io.WriteString(output, wireMagic); err != nil {
		return err
	}
	return writeAll(output, []byte{command})
}

func readRequest(input io.Reader) (byte, error) {
	magic := make([]byte, len(wireMagic))
	if _, err := io.ReadFull(input, magic); err != nil {
		return 0, err
	}
	if string(magic) != wireMagic {
		return 0, errors.New("invalid pa SSH protocol magic")
	}
	var command [1]byte
	if _, err := io.ReadFull(input, command[:]); err != nil {
		return 0, err
	}
	return command[0], nil
}

func writeBytes32(output io.Writer, data []byte) error {
	if len(data) > maxMessageBytes {
		return fmt.Errorf("message exceeds %d bytes", maxMessageBytes)
	}
	if err := binary.Write(output, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	return writeAll(output, data)
}

func readBytes32(input io.Reader, limit uint32) ([]byte, error) {
	var length uint32
	if err := binary.Read(input, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > limit {
		return nil, fmt.Errorf("message length %d exceeds limit %d", length, limit)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(input, data); err != nil {
		return nil, err
	}
	return data, nil
}

func writeAll(output io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := output.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
