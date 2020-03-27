package identity

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// HashAlgorithm represents the hashing algorithm used to hash the password
type HashAlgorithm uint32

const (
	SHA1 HashAlgorithm = iota
	SHA256
	SHA512
)

const (
	// DefaultSaltLength is the default salt length for new passwords
	DefaultSaltLength    = 16
	// DefaultIterations is the default number of iterations for new passwords
	DefaultIterations    = 10000
	// DefaultHashAlgorithm is the default hashing algorithm for new passwords
	DefaultHashAlgorithm = SHA256
	// DefaultNumBytes is the default number of bytes reserved for the subkey
	DefaultNumBytes      = 32
)

func getSalt(password []byte) []byte {
	saltLength := binary.BigEndian.Uint32(password[9:13])
	return password[13 : 13+saltLength]
}

func getSaltLength(password []byte) uint32 {
	return binary.BigEndian.Uint32(password[9:13])
}

func getHashAlgorithm(password []byte) HashAlgorithm {
	return HashAlgorithm(binary.BigEndian.Uint32(password[1:5]))
}

func getIterationCount(password []byte) uint32 {
	return binary.BigEndian.Uint32(password[5:9])
}

// GenerateSalt generates a cryptographically safe random salt of the specified length
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

// HashPassword hashes the given password with the specified salt, algorithm, number of iterations and hash length
func HashPassword(password, salt []byte, algorithm HashAlgorithm, iterations, numBytes int) []byte {
	saltLength := len(salt)

	subkey := pbkdf2.Key(password, salt, iterations, numBytes, func() hash.Hash {
		switch algorithm {
		case SHA1:
			return sha1.New()
		default:
			// SHA256 is default
			fallthrough
		case SHA256:
			return sha256.New()
		case SHA512:
			return sha512.New()
		}
	})

	result := make([]byte, 13 + saltLength + numBytes)
	result[0] = 1

	binary.BigEndian.PutUint32(result[1:5], uint32(algorithm))
	binary.BigEndian.PutUint32(result[5:9], uint32(iterations))
	binary.BigEndian.PutUint32(result[9:13], uint32(saltLength))
	copy(result[13:13 + saltLength], salt)
	copy(result[13 + saltLength:], subkey)

	return result
}

// VerifyPassword verifies the given hashed password against the given clear text password and returns true if they match
func VerifyPassword(hashedPassword []byte, clearPassword string) bool {
	salt := getSalt(hashedPassword)
	saltLength := int(getSaltLength(hashedPassword))
	iterations := int(getIterationCount(hashedPassword))
	algorithm := getHashAlgorithm(hashedPassword)
	subkeyLength := len(hashedPassword) - 13 - saltLength

	if subkeyLength < 32 {
		return false
	}

	actualHash := HashPassword([]byte(clearPassword), salt, algorithm, iterations, subkeyLength)
	return subtle.ConstantTimeCompare(hashedPassword, actualHash) == 1
}
