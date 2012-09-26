package main

import (
	"os"
	"strings"
)

func main() {

	switch {
	case len(os.Args) < 2:
		PrintGeneralUsage("Missing command")
	case strings.HasPrefix("client", os.Args[1]):
		Client(os.Args[2:])
	case strings.HasPrefix("server", os.Args[1]):
		Server(os.Args[2:])
	}
}
