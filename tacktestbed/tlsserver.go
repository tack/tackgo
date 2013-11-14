package main

import (
	"crypto/sha256"
	"crypto/x509"
	"net"
	"log"
	"io"
	"time"
	"github.com/tack/tackgo/tacktls"
	"github.com/tack/tackgo/tack"
)

type TlsServer struct { 
	cert tls.Certificate
	pinState *PinState
	talkChan chan string
	dataChan chan uint32
	listener net.Listener
	tcpListener *net.TCPListener
}

func NewTlsServer(certFile, keyFile *string, talkChan chan string, 
	dataChan chan uint32) *TlsServer {
	// Load X.509 certificates and key
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if (err != nil) {log.Fatal(err)}

	// Calculate targetHash	
	hashAlg := sha256.New()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic("")
	}
	hashAlg.Write(leaf.RawSubjectPublicKeyInfo)

	// Return new TlsServer
	tlsServer := TlsServer{cert, NewPinState(hashAlg.Sum(nil)), talkChan, dataChan, 
		nil, nil}
	return &tlsServer
}

func (tlsServer *TlsServer) listen() {
	var err error
	tlsServer.tcpListener, err = net.ListenTCP("tcp4", 
			&net.TCPAddr{IP: net.IPv4(127,0,0,1), Port: 8443})
	if err != nil {panic(err.Error())}
	tlsServer.reListen(true)
}

func (tlsServer *TlsServer) reListen(newTest bool) {
	// Create TackExtension and tls.Config
	if newTest {
		tlsServer.pinState = NewPinState(tlsServer.pinState.targetHash)
	} else {
		tlsServer.pinState.next()
	}

	tackExt, err := tack.NewTackExtension([]*tack.Tack{tlsServer.pinState.tack}, 1)
	if (err != nil) {panic(err.Error())}

	config := tls.Config{}
	config.Certificates = []tls.Certificate{tlsServer.cert}
	config.TackExtension = tackExt

	tlsServer.listener = tls.NewListener(tlsServer.tcpListener, &config)
}

func (tlsServer *TlsServer) run() {
	tlsServer.listen()
	for {
		// Wait for a new connection 
		tlsServer.tcpListener.SetDeadline(time.Now().Add(time.Millisecond))
		conn, err := tlsServer.listener.Accept()

		// If the call returned with err it's probably a timeout, check whether
		// a talkChan message has arrived, then continue waiting for a connection
		if err != nil {
			select {
			case s := <- tlsServer.talkChan:
				//fmt.Fprintf(os.Stderr, "tlsServer channel response %v\n", s)
				if s == "next" {
					tlsServer.reListen(false)
					tlsServer.talkChan <- "done"
					tlsServer.dataChan <- tlsServer.pinState.currentTime
				} else if s == "new" {
					tlsServer.reListen(true)
					tlsServer.talkChan <- "done"
					tlsServer.dataChan <- tlsServer.pinState.currentTime
				}
			default:
			}
			continue;
		}
		
		// No error: Run a goroutine to echo data on the new connection
		go func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
		}(conn)
	}	
}
