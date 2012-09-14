package main

import (
	"net"
	"crypto/tls"
	"log"
	"io"
)

func main() {
	
	certFile := "/Users/trevp/w/tlslite/tests/serverX509Cert.pem"
	keyFile := "/Users/trevp/w/tlslite/tests/serverX509Key.pem"
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if (err != nil) {log.Fatal(err)}
	
	config := tls.Config{Certificates : []tls.Certificate{cert}}
	
	l, err := tls.Listen("tcp", ":4443", &config)
	if err != nil {log.Fatal(err)}

	for {
	    // Wait for a connection. 
	    conn, err := l.Accept()
	    if err != nil {log.Fatal(err)}

	    go func(c net.Conn) {
	        io.Copy(c, c)
	        c.Close()
	    }(conn)
	}	
}
