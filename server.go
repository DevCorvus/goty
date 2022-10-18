package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrInternal = "Something went wrong"

	staticPath    = "./static"
	templatesPath = "./templates"

	userRepository UserRepository
)

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
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: ErrInternal})
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

		if user := userRepository.GetByUsername(username); user.ID != 0 {
			w.WriteHeader(http.StatusConflict)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: "Username already exists"})
			return

		}

		if _, err := userRepository.Create(User{Username: username, Password: password}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: ErrInternal})
			return
		}

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

func parseTemplate(fileName string) *template.Template {
	return template.Must(template.ParseFiles(filepath.Join(templatesPath, "/", fileName)))
}

func main() {
	db := initializeDatabase()
	defer db.Close()

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

type Repository interface {
	Migrate() error
}

type UserRepository struct {
	db *sql.DB
}

type User struct {
	ID        int64
	Username  string
	Password  string
	CreatedAt *time.Time
}

func (r *UserRepository) Migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
	);
	`

	_, err := r.db.Exec(query)
	return err
}

func (r *UserRepository) Create(user User) (*User, error) {
	res, err := r.db.Exec("INSERT INTO users(username, password) VALUES (?, ?)", user.Username, user.Password)
	if err != nil {
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	user.ID = id

	return &user, nil
}

func (r *UserRepository) GetByUsername(username string) *User {
	// For some reason, db.Exec doesn't always return RowsAffected correctly
	row := r.db.QueryRow("SELECT * FROM users WHERE username = ?", username)

	var user User
	row.Scan(&user.ID, &user.Username, &user.Password, &user.CreatedAt)

	return &user
}

func initializeDatabase() *sql.DB {
	db, err := sql.Open("sqlite3", "db.sqlite")

	if err != nil {
		panic(err)
	}

	userRepository = UserRepository{db: db}

	runMigrations(&userRepository)

	return db
}

func runMigrations(repos ...Repository) {
	for _, repo := range repos {
		if err := repo.Migrate(); err != nil {
			panic(err)
		}
	}
}
