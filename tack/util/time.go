package util

import (
	"time"
)

func MinutesToString(minutes uint32) string {
	t := time.Unix(int64(minutes) * 60, 0)
	utc := t.UTC()
	return utc.Format("2006-01-02T15:04Z")
}