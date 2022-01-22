package kube

import (
	"crypto/rand"
	"encoding/base64"
)

func MakeSignature(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		b = nil
	}
	// base64 encode it so signing key can be typed into validation utilities
	b = []byte(base64.StdEncoding.EncodeToString(b))
	return b, err
}
