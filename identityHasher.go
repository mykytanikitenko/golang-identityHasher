package identityHasher

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"golang.org/x/crypto/pbkdf2"
	"reflect"
)

const saltSize = 16
const hashIterations = 0x3e8
const keyLength = 32

func Hash(password string) (hashed string, err error) {
	salt, err := getRandomBytes(saltSize)
	if err != nil {
		return "", err
	}

	hash := pbkdf2.Key([]byte(password), salt, hashIterations, keyLength, sha1.New)

	zeroByteArray := [1]byte{0x0}
	zeroByteWithSalt := append(zeroByteArray[:], salt...)

	zeroByteWithSaltWithHash := append(zeroByteWithSalt, hash...)
	hashString := string(zeroByteWithSaltWithHash[:])

	return toBase64(hashString), nil
}

func ValidateHash(password string, passwordHash string) (bool, error) {
	decodedHash, err := base64.StdEncoding.DecodeString(passwordHash)
	if err != nil {
		return false, err
	}

	salt := decodedHash[1 : saltSize+1]
	hash := decodedHash[saltSize+1 : saltSize + 1 + keyLength]

	newHash := pbkdf2.Key([]byte(password), salt, hashIterations, keyLength, sha1.New)

	return reflect.DeepEqual(hash, newHash), nil
}

func toBase64(message string) string {
	return base64.StdEncoding.EncodeToString([]byte(message))
}

func getRandomBytes(buffetLength int) (result []byte, err error) {
	buffer := make([]byte, buffetLength)
	_, err = rand.Read(buffer)

	return buffer, err
}
