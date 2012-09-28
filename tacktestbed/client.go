package main

import (
	"fmt"
	"log"
	"net/http"
	"tacktls"
)

type TestClient struct { 

}


func NewTestClient() *TestClient {
	return &TestClient{}
}

func (client *TestClient) run() {

	config := tls.Config{}
	config.Tack = true
	config.InsecureSkipVerify = true

	for {
		// Make TLS connection
		conn, err := tls.Dial("tcp", "localhost:8443", &config)
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

		// Make HTTP request
		_, err = http.Get("http://localhost:8080/next")
	}
}
