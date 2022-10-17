package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var staticPath = "./static"
var templatesPath = "./templates"

type resData struct {
	Username string
	Message  string
	Error    string
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		t := parseTemplate("register.html")
		t.Execute(w, resData{})

	case "POST":
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		passwordConfirmation := r.FormValue("passwordConfirmation")

		if username == "" {
			w.WriteHeader(http.StatusBadRequest)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: "Username required"})
			return
		}
		if password == "" {
			w.WriteHeader(http.StatusBadRequest)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: "Password required"})
			return
		}
		if passwordConfirmation == "" {
			w.WriteHeader(http.StatusBadRequest)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: "Password confirmation required"})
			return
		}

		if len(username) < 4 || len(username) > 50 {
			w.WriteHeader(http.StatusBadRequest)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: "Username too short (<4) or too long (50>)"})
			return
		}
		if len(password) < 6 || len(password) > 200 {
			w.WriteHeader(http.StatusBadRequest)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: "Password too short (<6) or too long (200>)"})
			return
		}
		if passwordConfirmation != password {
			w.WriteHeader(http.StatusBadRequest)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: "Passwords do not match"})
			return
		}

		// TODO: Save new user

		url := fmt.Sprintf("/login?register=success&username=%s", username)
		http.Redirect(w, r, url, http.StatusSeeOther)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		query := r.URL.Query()
		register, username := query.Get("register"), query.Get("username")

		data := resData{}

		if register == "success" {
			data.Message = "Account created successfully"
		}
		if username != "" {
			data.Username = username
		}

		t := parseTemplate("login.html")
		t.Execute(w, data)

	case "POST":
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
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

	fileServer := http.FileServer(http.Dir(staticPath))
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

func parseTemplate(fileName string) *template.Template {
	return template.Must(template.ParseFiles(filepath.Join(templatesPath, "/", fileName)))
}
