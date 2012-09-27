package main

import (
	"crypto/sha256"
	"crypto/x509"
	"os"
	"fmt"
	"net"
	"log"
	"io"
	"time"
	"tacktls"
	"tack"
)

func tlsServer(certFile, keyFile *string, talkChan chan string) {

	// Load X.509 certificates and key
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if (err != nil) {log.Fatal(err)}
	
	hashAlg := sha256.New()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic("")
	}

	// Calculate targetHash
	hashAlg.Write(leaf.RawSubjectPublicKeyInfo)
	targetHash := hashAlg.Sum(nil)

	// Initialize pinState and get first tack
	pinState := NewPinState()
	t := pinState.new(targetHash)

	// Create TackExtension and tls.Config
	tackExt, err := tack.NewTackExtension([]*tack.Tack{t}, 1)
	if (err != nil) {panic("")}

	config := tls.Config{}
	config.Certificates = []tls.Certificate{cert}
	config.TackExtension = tackExt

	// Listen for new connection
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

					// If we got a "next" request, move to next PinState
					// and get new TackExtension, and listen again
					t = pinState.next(targetHash)
					tackExt, err = tack.NewTackExtension([]*tack.Tack{t}, 1)
					if (err != nil) {panic(err.Error())}

					config = tls.Config{}
					config.Certificates = []tls.Certificate{cert}
					config.TackExtension = tackExt
					
					tlsListener = tls.NewListener(tcpListener, &config)
					talkChan <- "done"
				}
			default:
			}
			continue;
		}
		
		// Run a goroutine to echo data on the new connection
		go func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
		}(conn)
	}
}
