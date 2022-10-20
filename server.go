package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrInternal = "Something went wrong"

	staticPath    = "./static"
	templatesPath = "./templates"

	// This should not be in source code
	cookieSecret = "super-secret-value-with-32-bytes"

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

		salt, err := generateSalt(16)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: ErrInternal})
			return
		}

		hashedPassword, err := hashPassword(password, salt)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("register.html")
			t.Execute(w, resData{Error: ErrInternal})
			return
		}

		userData := User{Username: username, Password: hashedPassword}

		if _, err := userRepository.Create(userData); err != nil {
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

		username := strings.Trim(r.FormValue("username"), " ")
		password := strings.Trim(r.FormValue("password"), " ")

		user := userRepository.GetByUsername(username)
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
			t.Execute(w, resData{Error: ErrInternal})
			return
		}

		if !doPasswordsMatch {
			w.WriteHeader(http.StatusUnauthorized)
			t := parseTemplate("login.html")
			t.Execute(w, resData{Error: "Username or Password incorrect"})
			return
		}

		if err := attachSessionCookie(w, user.ID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t := parseTemplate("login.html")
			t.Execute(w, resData{Error: ErrInternal})
			return
		}

		http.Redirect(w, r, "/games", http.StatusSeeOther)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		detachSessionCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func gamesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		t := parseTemplate("games.html")
		t.Execute(w, resData{})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func setupHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", userIsNotAuthenticated(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(staticPath, "/index.html"))
	}))
	mux.HandleFunc("/register", userIsNotAuthenticated(registerHandler))
	mux.HandleFunc("/login", userIsNotAuthenticated(loginHandler))
	mux.HandleFunc("/logout", userIsAuthenticated(logoutHandler))
	mux.HandleFunc("/games", userIsAuthenticated(gamesHandler))

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
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

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

type User struct {
	ID        int64
	Username  string
	Password  string
	CreatedAt *time.Time
}

func (user *User) ComparePassword(password string) (bool, error) {
	userPassword := strings.Split(user.Password, ":")

	salt, err := hex.DecodeString(userPassword[0])
	if err != nil {
		return false, err
	}

	hashedPassword, err := hashPassword(password, salt)
	if err != nil {
		return false, err
	}

	return user.Password == hashedPassword, nil
}

type UserRepository struct {
	db *sql.DB
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

func (r *UserRepository) GetById(id string) *User {
	row := r.db.QueryRow("SELECT * FROM users WHERE id = ?", id)

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

func generateSalt(saltSize int) ([]byte, error) {
	var salt = make([]byte, saltSize)

	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

// Don't use a manual hashing method (It's not safe). Instead, use something like bcrypt
func hashPassword(password string, salt []byte) (string, error) {
	passwordBytes := []byte(password)
	passwordBytesWithSalt := append(passwordBytes, salt...)

	sha512Hasher := sha512.New()

	if _, err := sha512Hasher.Write(passwordBytesWithSalt); err != nil {
		return "", err
	}

	hashedPasswordBytes := sha512Hasher.Sum(nil)

	saltHex := hex.EncodeToString(salt)
	hashedPasswordHex := hex.EncodeToString(hashedPasswordBytes)

	return saltHex + ":" + hashedPasswordHex, nil
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Another unsafe implementation (Don't do this yourself)
// FIXME: This doesn’t work as expected (probably because I’m dumb)
func encryptAES_GCM(secret, value string) (string, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(value), nil)

	return encodeBase64(ciphertext), nil
}

func decryptAES_GCM(secret, value string) (string, error) {
	ciphertext, err := decodeBase64(value)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func attachSessionCookie(w http.ResponseWriter, id int64) error {
	userId := strconv.FormatInt(id, 10)
	userIdEncrypted, err := encryptAES_GCM(cookieSecret, userId)
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:     "session",
		Path:     "/",
		Value:    userIdEncrypted,
		Secure:   false,
		HttpOnly: true,
		Expires:  time.Now().Add(time.Hour),
	}

	http.SetCookie(w, &cookie)
	return nil
}

func detachSessionCookie(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     "session",
		Path:     "/",
		Value:    "",
		Secure:   false,
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	}

	http.SetCookie(w, &cookie)
}

func userIsAuthenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userId, err := decryptAES_GCM(cookieSecret, cookie.Value)
		if err != nil {
			detachSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if user := userRepository.GetById(userId); user.ID == 0 {
			detachSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func userIsNotAuthenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err == nil {
			http.Redirect(w, r, "/games", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}
