package auth

import (
	"net/http"

	"github.com/DevCorvus/goty/internal/config"
	"github.com/DevCorvus/goty/internal/db"
	"github.com/DevCorvus/goty/internal/utils"
)

func UserIsAuthenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userId, err := utils.AES_GCM_Decrypt(config.CookieSecret, cookie.Value)
		if err != nil {
			DetachSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if user := db.User.GetById(userId); user.ID == 0 {
			DetachSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func UserIsNotAuthenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err == nil {
			http.Redirect(w, r, "/games", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}
