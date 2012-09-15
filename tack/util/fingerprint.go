package util

import (
	"strings"
	"fmt"
	"encoding/base32"
	"crypto/sha256"
)

func KeyFingerprint(b []byte) string {
	hash := sha256.New()
	hash.Write(b)
	s := strings.ToLower(base32.StdEncoding.EncodeToString(hash.Sum(nil)))
	return fmt.Sprintf("%s.%s.%s.%s.%s", s[:5],s[5:10],s[10:15],s[15:20],s[20:25])
}
