package config

import "path/filepath"

const (
	// This should not be in source code
	CookieSecret = "super-secret-value-with-32-bytes"
)

func GetStaticPath() string {
	path, _ := filepath.Abs("static")
	return path
}

func GetTemplatesPath() string {
	path, _ := filepath.Abs("templates")
	return path
}
