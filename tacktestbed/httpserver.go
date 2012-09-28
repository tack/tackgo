package main

import (
	"fmt"
	"net/http"
)

func httpServer(talkChan chan string, dataChan chan uint32) {

	handler := func(w http.ResponseWriter, r *http.Request) {
		request := r.URL.Path[1:]
		var currentTime uint32
		switch (request) {
		case "new":
			talkChan <- "new"
			_ = <- talkChan
			currentTime = <- dataChan
			fmt.Fprintf(w, "OK %d", currentTime)
		case "next":
			talkChan <- "next"
			_ = <- talkChan
			currentTime = <- dataChan
			fmt.Fprintf(w, "OK %d", currentTime)
		default:
			fmt.Fprintf(w, "Hi there, I don't know \"%s\"!", request)
		}
	}

    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}