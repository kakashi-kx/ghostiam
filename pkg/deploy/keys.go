package deploy

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
)

const accessKeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GenerateKeys produces a realistic AWS access key pair. The access key ID
// uses the AKIA prefix and the secret is a base32 blob, matching the shape of
// real AWS credentials without ever touching AWS itself.
func GenerateKeys() (accessKeyID, secretAccessKey string, err error) {
	akid, err := randomFromAlphabet(accessKeyAlphabet, 16)
	if err != nil {
		return "", "", fmt.Errorf("generate access key id: %w", err)
	}

	secret := make([]byte, 30)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("generate secret access key: %w", err)
	}

	return "AKIA" + akid, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// randomFromAlphabet returns a random string of length n whose characters are
// drawn uniformly from the given alphabet, backed by crypto/rand.
func randomFromAlphabet(alphabet string, n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	out := make([]byte, n)
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	mod := uint32(len(alphabet))
	for i := 0; i < n; i++ {
		out[i] = alphabet[int(raw[i])%int(mod)]
	}
	return string(out), nil
}
