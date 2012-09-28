package main

import (
	"log"
	"os"
	"fmt"
	"flag"
)

func PrintGeneralUsage(message string) {
	if len(message) > 0 {
		fmt.Printf("Error: %s\n", message)
	}
	fmt.Printf(`tackgo version %s (%s)

Commands (use "help <command>" to see optional args):
  genkey
  sign     -k KEY -c CERT
  view     FILE
  help     COMMAND
("pack" and "unpack" are advanced commands for debugging)
`, "0.0", "Go crypto")
	os.Exit(1)
}

func Client(args []string) {

	testClient := NewTestClient()
	testClient.run()
}

func Server(args [] string) error {

	// Parse cmdline args
	flagSet := flag.NewFlagSet("", flag.ExitOnError)
	certFile := flagSet.String("c", "", "X.509 certificate (PEM)")
	keyFile := flagSet.String("k", "", "Private key (PEM)")
	err := flagSet.Parse(args)
	if err != nil || *certFile == "" || *keyFile == "" || len(flagSet.Args()) != 0 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	// Run the servers with "talkChan" connecting them
	talkChan := make(chan string)
	tlsServer := NewTlsServer(certFile, keyFile, talkChan)
	go tlsServer.run()
	log.Println("TLS Server launched on 8443")

	go httpServer(talkChan)
	log.Println("HTTP Server launched on 8080")

	// Wait endlessly
	endChan := make(chan int)
	_ = <- endChan
	return nil
}
