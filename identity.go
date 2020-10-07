package identity

import (
	"crypto/rand"
)

// GenerateSalt generates a cryptographically safe random salt of the specified length
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

func Verify(hashedPassword, clearPassword []byte) bool {
	if len(hashedPassword) == 0 {
		return false
	}

	switch hashedPassword[0] {
	case 0:
		return VerifyPasswordV2(hashedPassword, clearPassword)

	case 1:
		return VerifyPasswordV3(hashedPassword, clearPassword)

	default:
		return false
	}
}
