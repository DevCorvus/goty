package utils

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
)

func GenerateSalt(saltSize int) ([]byte, error) {
	var salt = make([]byte, saltSize)

	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

// Don't use a manual hashing method (It's not safe). Instead, use something like bcrypt
func HashPassword(password string, salt []byte) (string, error) {
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
