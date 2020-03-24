package main

import (
	"fmt"
	"log"
	"os"

	auth "github.com/microapis/auth-api/run"
)

func main() {
	host := os.Getenv("HOST")
	if host == "" {
		log.Fatal("Env variable HOST must be defined")
	}

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("Env variable PORT must be defined")
	}

	addr := fmt.Sprintf("%s:%s", host, port)

	postgresDSN := os.Getenv("POSTGRES_DSN")
	if postgresDSN == "" {
		log.Fatal("POSTGRES_DSN env must be defined")
	}

	usersHost := os.Getenv("USERS_HOST")
	if usersHost == "" {
		log.Fatal("USERS_HOST env must be defined")
	}

	usersPort := os.Getenv("USERS_PORT")
	if usersPort == "" {
		log.Fatal("USERS_PORT env must be defined")
	}

	usersAddr := fmt.Sprintf("%s:%s", usersHost, usersPort)

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET env must be defined")
	}

	auth.Run(addr, postgresDSN, usersAddr)
}
