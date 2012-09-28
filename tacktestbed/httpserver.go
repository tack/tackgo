package main

import (
	"fmt"
	"net/http"
)

func httpServer(talkChan chan string) {

	handler := func(w http.ResponseWriter, r *http.Request) {
		request := r.URL.Path[1:]
		switch (request) {
		case "new":
			talkChan <- "new"
			_ = <- talkChan
			fmt.Fprintf(w, "OK new")
		case "next":
			talkChan <- "next"
			_ = <- talkChan
			fmt.Fprintf(w, "OK next")
		default:
			fmt.Fprintf(w, "Hi there, I don't know \"%s\"!", request)
		}
	}

    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}