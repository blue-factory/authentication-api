package database

import (
	"github.com/jmoiron/sqlx"
	auth "github.com/microapis/authentication-api"
	"github.com/microapis/authentication-api/database/postgres"
)

// Store ...
type Store interface {
	Get(*auth.Query) (*auth.Auth, error)
	Create(*auth.Auth) error
	List() ([]*auth.Auth, error)
	Update(*auth.Auth) error
	Delete(a *auth.Auth) error
}

// NewPostgres ...
func NewPostgres(dsn string) (Store, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	return &postgres.AuthStore{
		Store: db,
	}, nil
}
