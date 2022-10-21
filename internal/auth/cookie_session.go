package auth

import (
	"net/http"
	"strconv"
	"time"

	"github.com/DevCorvus/goty/internal/config"
	"github.com/DevCorvus/goty/internal/utils"
)

func AttachSessionCookie(w http.ResponseWriter, id int64) error {
	userId := strconv.FormatInt(id, 10)
	userIdEncrypted, err := utils.AES_GCM_Encrypt(config.CookieSecret, userId)
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

func DetachSessionCookie(w http.ResponseWriter) {
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
