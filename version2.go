package identity

import (
	"crypto/sha1"
	"crypto/subtle"
	"golang.org/x/crypto/pbkdf2"
)

func HashPasswordV2(password, salt []byte) []byte {
	subkey := pbkdf2.Key(password, salt, 1000, 32, sha1.New)

	result := make([]byte, 49)
	result[0] = 0
	copy(result[1:17], salt)
	copy(result[17:49], subkey)

	return result
}

func VerifyPasswordV2(hashedPassword, clearPassword []byte) bool {
	salt, err := getSliceSafe(hashedPassword, 1, 17)
	if err != nil {
		return false
	}

	actualHash := HashPasswordV2(clearPassword, salt)
	success := subtle.ConstantTimeCompare(actualHash, hashedPassword) == 1

	return success
}
