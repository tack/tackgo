package util

import (
	"encoding/hex"
)

func BytesToHexString(b []byte) string {
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
