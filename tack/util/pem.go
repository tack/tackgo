package util

import (
	"encoding/base64"
	"fmt"
	"strings"
	"errors"
)

func Pem(b []uint8, name string) string {
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

func Depem(s string, name string) ([]byte, error) {
	prefix := fmt.Sprintf("-----BEGIN %s-----", name)
	postfix := fmt.Sprintf("-----END %s-----", name)
	
	s = strings.Replace(s, "\n", "", -1)
	start := strings.Index(s, prefix)
	if start == -1 {
		return nil, errors.New("Missing PEM prefix")
	}
	end := strings.Index(s, postfix)
	if end == -1 {
		return nil, errors.New("Missing PEM postfix")
	}
	if end < start {
		return nil, errors.New("PEM postfix before prefix")
	}
	
	body := s[start + len(prefix) : end]
	return base64.StdEncoding.DecodeString(body)
}
