package crypto

import (
	"encoding/binary"
	"errors"
)

const (
	padBucket            = 256
	maxPaddedMessageSize = 64 * 1024
)

func Pad(packed []byte) ([]byte, error) {
	base := 4 + len(packed)
	target := ((base + padBucket - 1) / padBucket) * padBucket

	if target > maxPaddedMessageSize {
		return nil, errors.New("message too large")
	}

	out := make([]byte, target)
	binary.BigEndian.PutUint32(out[:4], uint32(len(packed)))
	copy(out[4:], packed)

	if paddingLen := target - base; paddingLen > 0 {
		padding, err := RandomBytes(paddingLen)
		if err != nil {
			return nil, err
		}
		copy(out[base:], padding)
	}

	return out, nil
}

func Unpad(plaintext []byte) ([]byte, error) {
	if len(plaintext) < 4 {
		return nil, errors.New("padded message too short")
	}

	n := binary.BigEndian.Uint32(plaintext[:4])
	if uint64(n) > uint64(len(plaintext)-4) {
		return nil, errors.New("invalid padded message length")
	}

	return plaintext[4 : 4+int(n)], nil
}
