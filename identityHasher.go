package identityHasher

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"

	"bytes"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize       = 16
	hashIterations = 0x3e8
	keyLength      = 32
)

func Hash(password string) (hashed string, err error) {
	salt, err := getRandomBytes(saltSize)
	if err != nil {
		return "", err
	}

	hash := pbkdf2.Key([]byte(password), salt, hashIterations, keyLength, sha1.New)
	zeroByteWithSaltWithHash := append([]byte{0x0}, append(salt, hash...)...)
	hashed = base64.StdEncoding.EncodeToString(zeroByteWithSaltWithHash[:])
	return
}

func ValidateHash(password string, passwordHash string) (isEqual bool, err error) {
	decodedHash, err := base64.StdEncoding.DecodeString(passwordHash)
	if err != nil {
		isEqual = false
		return
	}

	salt := decodedHash[1 : saltSize+1]
	hash := decodedHash[saltSize+1 : saltSize+1+keyLength]

	newHash := pbkdf2.Key([]byte(password), salt, hashIterations, keyLength, sha1.New)
	isEqual = bytes.Equal(hash, newHash)
	return
}

func getRandomBytes(buffetLength int) (result []byte, err error) {
	result = make([]byte, buffetLength)
	_, err = rand.Read(result)
	return
}
