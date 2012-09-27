package main

import (
	"fmt"
	"os"
	"net/http"
)

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