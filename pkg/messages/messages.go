package messages

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/slipe-fun/skid-v4/internal/crypto"
	"github.com/slipe-fun/skid-v4/pkg/identity"
	"github.com/slipe-fun/skid-v4/pkg/protocol"
	"github.com/vmihailenco/msgpack/v5"
)

type EncryptedMessage struct {
	Version    []byte
	Ciphertext []byte
	Nonce      []byte
	Salt       []byte
}

type Message struct {
	Content   []byte
	AuthorID  string
	SyncTag   []byte
	Timestamp int64 // Unix milliseconds
}

func Pack(m *Message) ([]byte, error) {
	return msgpack.Marshal(m)
}

func Unpack(packed []byte) (*Message, error) {
	var m Message
	err := msgpack.Unmarshal(packed, &m)
	return &m, err
}

func Encrypt(key, content, syncKey []byte, me, recipient *identity.User) (*EncryptedMessage, error) {
	if err := me.Validate(); err != nil {
		return nil, fmt.Errorf("sender: %s", err)
	}

	if err := recipient.Validate(); err != nil {
		return nil, fmt.Errorf("sender: %s", err)
	}

	if len(key) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}
	if len(syncKey) == 0 {
		return nil, errors.New("sync key cannot be empty")
	}

	var (
		derivedKey    []byte
		payloadData   []byte
		packedMessage []byte
		err           error
	)

	defer func() {
		crypto.Zero(derivedKey)
		crypto.Zero(payloadData)
		crypto.Zero(packedMessage)
	}()

	version := protocol.Current

	salt, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	messageInfo, err := crypto.GenerateMessageInfo(version, me.ID, recipient.ID)
	if err != nil {
		return nil, err
	}

	derivedKey, err = crypto.HKDF(key, salt, messageInfo, 32)
	if err != nil {
		return nil, err
	}

	firstID := me.ID
	secondID := recipient.ID
	if secondID < firstID {
		firstID = recipient.ID
		secondID = me.ID
	}

	messageAAD := crypto.BuildAAD("message",
		version,
		[]byte(firstID),
		[]byte(secondID),
	)

	timestamp := time.Now().UnixMilli()

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))

	payloadData = crypto.ConcatBytes(timestampBytes, []byte(me.ID), content)

	syncTag, err := crypto.ComputeHMAC(syncKey, payloadData)
	if err != nil {
		return nil, err
	}

	message := Message{
		Content:   content,
		AuthorID:  me.ID,
		SyncTag:   syncTag,
		Timestamp: timestamp,
	}

	packedMessage, err = Pack(&message)
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.Pad(packedMessage)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(plaintext)

	ciphertext, nonce, err := crypto.Encrypt(derivedKey, plaintext, messageAAD)
	if err != nil {
		return nil, err
	}

	return &EncryptedMessage{
		Version:    version.Bytes(),
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       salt,
	}, nil
}

func Decrypt(key []byte, encryptedMessage EncryptedMessage, syncKey []byte, me, recipient *identity.User) (*Message, error) {
	if err := me.Validate(); err != nil {
		return nil, fmt.Errorf("sender: %s", err)
	}

	if err := recipient.Validate(); err != nil {
		return nil, fmt.Errorf("sender: %s", err)
	}

	if len(key) == 0 {
		return nil, errors.New("decryption key cannot be empty")
	}
	if len(syncKey) == 0 {
		return nil, errors.New("sync key cannot be empty")
	}
	if len(encryptedMessage.Ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}
	if len(encryptedMessage.Nonce) == 0 {
		return nil, errors.New("nonce cannot be empty")
	}
	if len(encryptedMessage.Salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	var (
		derivedKey      []byte
		packedMessage   []byte
		unpackedMessage *Message
		payloadData     []byte
		err             error
	)

	defer func() {
		crypto.Zero(derivedKey)
		crypto.Zero(packedMessage)
		crypto.Zero(payloadData)
	}()

	version, err := protocol.Parse(encryptedMessage.Version)
	if err != nil {
		return nil, err
	}
	if err := version.Check(); err != nil {
		return nil, err
	}

	messageInfo, err := crypto.GenerateMessageInfo(version, me.ID, recipient.ID)
	if err != nil {
		return nil, err
	}

	derivedKey, err = crypto.HKDF(key, encryptedMessage.Salt, messageInfo, 32)
	if err != nil {
		return nil, err
	}

	firstID := me.ID
	secondID := recipient.ID
	if secondID < firstID {
		firstID = recipient.ID
		secondID = me.ID
	}

	messageAAD := crypto.BuildAAD("message",
		version,
		[]byte(firstID),
		[]byte(secondID),
	)

	plaintext, err := crypto.Decrypt(derivedKey, encryptedMessage.Ciphertext, encryptedMessage.Nonce, messageAAD)
	if err != nil {
		return nil, err
	}

	packedMessage, err = crypto.Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	unpackedMessage, err = Unpack(packedMessage)
	if err != nil {
		return nil, err
	}

	timestampBytes := make([]byte, 8) // Unix milliseconds
	binary.BigEndian.PutUint64(timestampBytes, uint64(unpackedMessage.Timestamp))

	payloadData = crypto.ConcatBytes(timestampBytes, []byte(me.ID), unpackedMessage.Content)

	syncTag, err := crypto.ComputeHMAC(syncKey, payloadData)
	if err != nil {
		return nil, err
	}

	if hmac.Equal(unpackedMessage.SyncTag, syncTag) {
		unpackedMessage.AuthorID = me.ID
	} else {
		unpackedMessage.AuthorID = recipient.ID
	}

	return unpackedMessage, nil
}
