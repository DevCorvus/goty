package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/DevCorvus/goty/internal/config"
	"github.com/DevCorvus/goty/internal/db"
	"github.com/DevCorvus/goty/internal/handlers"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	dbConn := db.Initialize()
	defer dbConn.Close()

	listenAddr := getListenAddr()

	mux := http.NewServeMux()

	fileServer := http.FileServer(http.Dir(config.GetStaticPath()))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

	handlers.Setup(mux)

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
