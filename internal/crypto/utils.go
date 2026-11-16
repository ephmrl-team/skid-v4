package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"github.com/slipe-fun/skid-v4/pkg/protocol"
	"golang.org/x/crypto/blake2b"
)

const authTokenLabel = "skid:auth:token"

func ConcatBytes(fields ...[]byte) []byte {
	totalLen := 0
	for _, f := range fields {
		totalLen += 4 + len(f)
	}

	res := make([]byte, totalLen)
	offset := 0
	for _, f := range fields {
		binary.BigEndian.PutUint32(res[offset:offset+4], uint32(len(f)))
		offset += 4
		copy(res[offset:], f)
		offset += len(f)
	}
	return res
}

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func HashPublicKeys(ecdhPK, mlkemPK []byte) []byte {
	combined := make([]byte, len(ecdhPK)+len(mlkemPK))
	copy(combined, ecdhPK)
	copy(combined[len(ecdhPK):], mlkemPK)

	hash := blake2b.Sum256(combined)
	return hash[:10]
}

func DeriveAuthLookupID(recoveryKey []byte) []byte {
	var recoveryKeyCopy []byte

	recoveryKeyCopy = make([]byte, len(recoveryKey))
	copy(recoveryKeyCopy, recoveryKey)

	defer Zero(recoveryKeyCopy)

	h := hmac.New(sha256.New, recoveryKeyCopy)
	h.Write([]byte(authTokenLabel))
	mac := h.Sum(nil)

	return mac[:16]
}

func GenerateMessageInfo(version protocol.Version, idA, idB string) (string, error) {
	if idA == "" || idB == "" {
		return "", errors.New("info generator: user IDs cannot be empty")
	}

	first := idA
	second := idB

	if idB < idA {
		first = idB
		second = idA
	}

	infoString := fmt.Sprintf("%s:%s:%s", version.Label("message"), first, second)
	return infoString, nil
}
