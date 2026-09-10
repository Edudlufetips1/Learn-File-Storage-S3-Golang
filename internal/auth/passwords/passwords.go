package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength   = 128
	memoryKiB   = 19 * 1024
	iterations  = 2
	parallelism = 1
	saltLength  = 16
	keyLength   = 32
)

func Hash(password string) (string, error) {
	if len(password) > MaxLength {
		return "", errors.New("password exceeds maximum length")
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, iterations, memoryKiB, parallelism, keyLength)
	passwordHash := argon2idHash{
		version:     argon2.Version,
		memoryKiB:   memoryKiB,
		iterations:  iterations,
		parallelism: parallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}
	return encodeArgon2idHash(passwordHash), nil
}

func Verify(password, encodedHash string) bool {
	if len(password) > MaxLength {
		return false
	}
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}
	parseArgonHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}

	if parseArgonHash.version != argon2.Version {
		return false
	}
	candidateKey := argon2.IDKey(
		[]byte(password),
		parseArgonHash.salt,
		parseArgonHash.iterations,
		parseArgonHash.memoryKiB,
		parseArgonHash.parallelism,
		uint32(len(parseArgonHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(candidateKey, parseArgonHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if parsedHash.memoryKiB != memoryKiB ||
		parsedHash.iterations != iterations ||
		parsedHash.parallelism != parallelism ||
		uint32(len(parsedHash.derivedKey)) != keyLength {
		return true
	}
	return false
}
