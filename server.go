package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func setupHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Game of the year")
	})

	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func main() {
	listenAddr := getListenAddr()

	mux := http.NewServeMux()

	setupHandlers(mux)

	fmt.Printf("Listening... http://localhost%s\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func getListenAddr() string {
	listenAddr := ":"

	port := os.Getenv("PORT")
	if len(port) > 0 {
		listenAddr += port
	} else {
		listenAddr += "8080"
	}

	return listenAddr
}
