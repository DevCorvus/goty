package db

import (
	"database/sql"

	"github.com/DevCorvus/goty/internal/models"
)

var User *models.UserRepository

func Initialize() *sql.DB {
	db, err := sql.Open("sqlite3", "db.sqlite")

	if err != nil {
		panic(err)
	}

	User = models.NewUserRepository(db)

	runMigrations(User)

	return db
}

type repository interface {
	Migrate() error
}

func runMigrations(repos ...repository) {
	for _, repo := range repos {
		if err := repo.Migrate(); err != nil {
			panic(err)
		}
	}
}
