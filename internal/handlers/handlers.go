package handlers

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/DevCorvus/goty/internal/auth"
	"github.com/DevCorvus/goty/internal/config"
	"github.com/DevCorvus/goty/internal/db"
	"github.com/DevCorvus/goty/internal/models"
	"github.com/DevCorvus/goty/internal/utils"
)

const errInternal = "Something went wrong"

type resData struct {
	Username string
	Message  string
	Error    string
}

func Setup(mux *http.ServeMux) {
	mux.HandleFunc("/", auth.UserIsNotAuthenticated(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(config.GetStaticPath(), "/index.html"))
	}))
	mux.HandleFunc("/register", auth.UserIsNotAuthenticated(register))
	mux.HandleFunc("/login", auth.UserIsNotAuthenticated(login))
	mux.HandleFunc("/logout", auth.UserIsAuthenticated(logout))
	mux.HandleFunc("/games", auth.UserIsAuthenticated(games))

	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func register(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		t := parseTemplate("register.html")
		t.Execute(w, resData{})

	case "POST":
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: errInternal})
			return
		}

		username := strings.Trim(r.FormValue("username"), " ")
		password := strings.Trim(r.FormValue("password"), " ")
		passwordConfirmation := strings.Trim(r.FormValue("passwordConfirmation"), " ")

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

		if user := db.User.GetByUsername(username); user.ID != 0 {
			w.WriteHeader(http.StatusConflict)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: "Username already exists"})
			return
		}

		salt, err := utils.GenerateSalt(16)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: errInternal})
			return
		}

		hashedPassword, err := utils.HashPassword(password, salt)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: errInternal})
			return
		}

		userData := models.User{Username: username, Password: hashedPassword}

		if _, err := db.User.Create(userData); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: errInternal})
			return
		}

		url := fmt.Sprintf("/login?register=success&username=%s", username)
		http.Redirect(w, r, url, http.StatusSeeOther)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
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

		username := strings.Trim(r.FormValue("username"), " ")
		password := strings.Trim(r.FormValue("password"), " ")

		user := db.User.GetByUsername(username)
		if user.ID == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			t := parseTemplate("login.html")
			t.Execute(w, resData{Error: "Username or Password incorrect"})
			return
		}

		doPasswordsMatch, err := user.ComparePassword(password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("login.html")
			t.Execute(w, resData{Error: errInternal})
			return
		}

		if !doPasswordsMatch {
			w.WriteHeader(http.StatusUnauthorized)
			t := parseTemplate("login.html")
			t.Execute(w, resData{Error: "Username or Password incorrect"})
			return
		}

		if err := auth.AttachSessionCookie(w, user.ID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("login.html")
			t.Execute(w, resData{Error: errInternal})
			return
		}

		http.Redirect(w, r, "/games", http.StatusSeeOther)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		auth.DetachSessionCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func games(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		t := parseTemplate("games.html")
		t.Execute(w, resData{})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func parseTemplate(fileName string) *template.Template {
	return template.Must(template.ParseFiles(filepath.Join(config.GetTemplatesPath(), "/", fileName)))
}
