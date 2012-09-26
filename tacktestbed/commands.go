package main

import (
	"os"
	"fmt"
	"flag"
	"net"
	"net/http"
	"log"
	"io"
	"time"
	"tacktls"
	"tack"
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
	config := tls.Config{}
	config.Tack = true
	config.InsecureSkipVerify = true

	conn, err := tls.Dial("tcp", "test.tack.io:443", &config)
	if err != nil {log.Fatal(err)}

	err = conn.Handshake()
	if err != nil {log.Fatal(err)}

	connState := conn.ConnectionState()
	if connState.TackExtension != nil {
		te := connState.TackExtension
		fmt.Println(te)
	} else {
		fmt.Println("No Tack Extension")
	}

}

func Server(args [] string) error {

	flagSet := flag.NewFlagSet("", flag.ExitOnError)

	certFile := flagSet.String("c", "", "X.509 certificate (PEM)")
	keyFile := flagSet.String("k", "", "Private key (PEM)")
	tackExtFile := flagSet.String("e", "", "TackExtension")

	err := flagSet.Parse(args)
	if err != nil || *certFile == "" || *keyFile == "" || len(flagSet.Args()) != 0 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	talkChan := make(chan string)

	go tlsServer(certFile, keyFile, tackExtFile, talkChan)
	log.Println("TLS Server launched on 8443")

	go httpServer(talkChan)
	log.Println("HTTP Server launched on 8080")

	endChan := make(chan int)
	_ = <- endChan // Wait endlessly for goroutines

	return nil
}

func tlsServer(certFile, keyFile, tackExtFile *string, talkChan chan string) {

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if (err != nil) {log.Fatal(err)}
	
	f, err := os.Open(*tackExtFile)
	if err != nil {log.Fatal(err)}

	tackExtBytes := make([]byte, 1024)
	nbytes, err := f.Read(tackExtBytes)
	if err != nil {log.Fatal(err)}

	tackExt, err := tack.NewTackExtensionFromPem(string(tackExtBytes[:nbytes])) 
	if err != nil {log.Fatal(err)}

	config := tls.Config{}
	config.Certificates = []tls.Certificate{cert}
	config.TackExtension = tackExt

	tcpListener, err:= net.ListenTCP("tcp4", &net.TCPAddr{net.IPv4(127,0,0,1), 8443})
	if err != nil {log.Fatal(err)}
	tlsListener := tls.NewListener(tcpListener, &config)

	for {
		// Wait for a new connection 
		tcpListener.SetDeadline(time.Now().Add(time.Second))
		conn, err := tlsListener.Accept()

		// If the call returned with err it could b a timeout, check whether
		// a talkChan message has arrived
		if err != nil {
			select {
			case s := <-talkChan:
				fmt.Fprintf(os.Stderr, "tlsServer channel response %v\n", s)
				if s == "next" {
					config = tls.Config{}
					config.Certificates = []tls.Certificate{cert}
					tlsListener = tls.NewListener(tcpListener, &config)
					talkChan <- "done"
				}
			default:
			}
			continue;
		}
		
		// Run a goroutine to handle the new connection
		go func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
		}(conn)
	}
}

func httpServer(talkChan chan string) {

	handler := func(w http.ResponseWriter, r *http.Request) {
		request := r.URL.Path[1:]
		switch (request) {
			/*
		case "new":
			talkChan <- "new"
			s := <- talkChan
			fmt.Fprintf(os.Stderr, "httpServer channel response %v\n", s)
			 */
		case "next":
			talkChan <- "next"
			s := <- talkChan
			fmt.Fprintf(os.Stderr, "httpServer channel response %v\n", s)
			fmt.Fprintf(w, "OK next")
		default:
			fmt.Fprintf(w, "Hi there, I don't know \"%s\"!", request)
		}
	}

    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}