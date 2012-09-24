package main

import (
	"os"
	"strings"
	"tackgo/tack/commands"
)

func main() {

	switch {
	case len(os.Args) < 2:
		commands.PrintGeneralUsage("Missing command")
	case strings.HasPrefix("client", os.Args[1]):
		commands.Client(os.Args[2:])
	case strings.HasPrefix("server", os.Args[1]):
		commands.Server(os.Args[2:])
	}
}
