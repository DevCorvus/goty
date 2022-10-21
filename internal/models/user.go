package models

import (
	"database/sql"
	"encoding/hex"
	"strings"
	"time"

	"github.com/DevCorvus/goty/internal/utils"
)

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

	hashedPassword, err := utils.HashPassword(password, salt)
	if err != nil {
		return false, err
	}

	return user.Password == hashedPassword, nil
}

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
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
