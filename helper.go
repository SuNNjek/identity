package identity

import (
	"encoding/base64"
	"errors"
)

func generateFakeSalt(length int) []byte {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = byte(i)
	}

	return result
}

func base64Decode(str string) []byte {
	if res, err := base64.StdEncoding.DecodeString(str); err != nil {
		panic(err)
	} else {
		return res
	}
}

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
