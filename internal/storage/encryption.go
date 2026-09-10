package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	aesKey, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aesGCM, err := cipher.NewGCM(aesKey)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aesGCM.Seal(nil, nonce, plaintext, nil)
	tagSize := aesGCM.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]
	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: ciphertext,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce size")
	}
	if len(payload.AuthTag) != 16 {
		return nil, fmt.Errorf("invalid auth tag size")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)

	plaintext, err := aesGCM.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
