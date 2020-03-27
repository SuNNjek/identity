package identity

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"math"

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

func getSliceSafe(s []byte, start, end uint32) ([]byte, error) {
	if start < 0 {
		return nil, errors.New("start index cannot be below zero")
	}

	l := uint32(len(s))
	if end >= l {
		return nil, errors.New("end index cannot exceed slice length")
	}

	return s[start:end], nil
}

func getSalt(password []byte) ([]byte, error) {
	saltLength := binary.BigEndian.Uint32(password[9:13])
	return getSliceSafe(password, 13, 13 + saltLength)
}

func getSaltLength(password []byte) (int, error) {
	if saltBytes, err := getSliceSafe(password, 9, 13); err != nil {
		return 0, err
	} else {
		return int(binary.BigEndian.Uint32(saltBytes)), nil
	}
}

func getHashAlgorithm(password []byte) (HashAlgorithm, error) {
	if algoBytes, err := getSliceSafe(password, 1, 5); err != nil {
		return math.MaxUint32, err
	} else {
		return HashAlgorithm(binary.BigEndian.Uint32(algoBytes)), nil
	}
}

func getIterationCount(password []byte) (int, error) {
	if iterBytes, err := getSliceSafe(password, 5, 9); err != nil {
		return 0, err
	} else {
		return int(binary.BigEndian.Uint32(iterBytes)), nil
	}
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
	salt, err := getSalt(hashedPassword)
	if err != nil {
		return false
	}

	saltLength, err := getSaltLength(hashedPassword)
	if err != nil {
		return false
	}

	iterations, err := getIterationCount(hashedPassword)
	if err != nil {
		return false
	}

	algorithm, err := getHashAlgorithm(hashedPassword)
	if err != nil {
		return false
	}

	subkeyLength := len(hashedPassword) - 13 - saltLength
	if subkeyLength < 32 {
		return false
	}

	actualHash := HashPassword([]byte(clearPassword), salt, algorithm, iterations, subkeyLength)
	success := subtle.ConstantTimeCompare(hashedPassword, actualHash) == 1
	return success
}
