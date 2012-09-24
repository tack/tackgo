package tack

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func bytesToHexString(b []byte) string {
	retVal := ""
	for s := hex.EncodeToString(b); len(s) != 0; {
		howMany := 32
		if len(s) < howMany {
			howMany = len(s)
		}
		retVal += s[:howMany]
		s = s[howMany:]
		if len(s) != 0 {
			retVal += "\n                  "
		}
	}
	return retVal
}

func pem(b []uint8, name string) string {
	s1 := base64.StdEncoding.EncodeToString(b)
	s2 := ""
	for len(s1) != 0 {
		lineLength := 64
		if len(s1) < 64 {
			lineLength = len(s1)
		}
		s2 += s1[:lineLength] + "\n"
		s1 = s1[lineLength:]
	}
	return fmt.Sprintf("-----BEGIN %s-----\n%s-----END %s-----\n",
		name, s2, name)
}

func depem(s string, name string) ([]byte, error) {
	prefix := fmt.Sprintf("-----BEGIN %s-----", name)
	postfix := fmt.Sprintf("-----END %s-----", name)

	s = strings.Replace(s, "\n", "", -1)
	start := strings.Index(s, prefix)
	if start == -1 {
		return nil, PemError{"Missing PEM prefix"}
	}
	end := strings.Index(s, postfix)
	if end == -1 {
		return nil, PemError{"Missing PEM postfix"}
	}
	if end < start {
		return nil, PemError{"PEM postfix before prefix"}
	}

	body := s[start+len(prefix) : end]
	return base64.StdEncoding.DecodeString(body)
}

func minutesToString(minutes uint32) string {
	t := time.Unix(int64(minutes)*60, 0)
	utc := t.UTC()
	return utc.Format("2006-01-02T15:04Z")
}
