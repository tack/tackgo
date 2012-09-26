package tack

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

type KeyFingerprint string

func NewKeyFingerprintFromBytes(b []byte) KeyFingerprint {
	hash := sha256.New()
	hash.Write(b)
	s := strings.ToLower(base32.StdEncoding.EncodeToString(hash.Sum(nil)))
	return KeyFingerprint(fmt.Sprintf("%s.%s.%s.%s.%s",
		s[:5], s[5:10], s[10:15], s[15:20], s[20:25]))
}

func NewKeyFingerprintFromString(s string) (KeyFingerprint, error) {
	for count, c := range s {
		if count == 5 || count == 11 || count == 17 || count == 23 {
			if c != '.' {
				return "", FingerprintError{}
			}
			continue
		}
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '2' && c <= '7' {
			continue
		}
		return "", FingerprintError{}
	}
	return KeyFingerprint(s), nil
}
