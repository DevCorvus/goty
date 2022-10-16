package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var static = "./static"

func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, filepath.Join(static, "/register.html"))

	case "POST":
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		// TODO: Handle data properly
		fmt.Fprintf(w, "%v", r.PostForm)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, filepath.Join(static, "/login.html"))

	case "POST":
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		// TODO: Handle data properly
		fmt.Fprintf(w, "%v", r.PostForm)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func setupHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)

	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func main() {
	listenAddr := getListenAddr()

	mux := http.NewServeMux()

	fileServer := http.FileServer(http.Dir(static))
	mux.Handle("/", fileServer)

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
