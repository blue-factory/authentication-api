package postgres

import (
	"database/sql"
	"errors"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jmoiron/sqlx"
	"github.com/microapis/auth-api"
)

// AuthStore ...
type AuthStore struct {
	Store *sqlx.DB
}

// Get ...
func (as *AuthStore) Get(q *auth.Query) (*auth.Auth, error) {
	query := squirrel.Select("*").From("auth").Where("deleted_at is null")

	if q.Email == "" && q.Token == "" && q.UserID == "" {
		return nil, errors.New("must proovide a query")
	}

	if q.Email != "" {
		query = query.Where("email = ?", q.Token)
	}

	if q.Token != "" {
		query = query.Where("token = ?", q.Token)
	}

	if q.UserID != "" {
		query = query.Where("user_id = ?", q.UserID)
	}

	sql, args, err := query.PlaceholderFormat(squirrel.Dollar).ToSql()
	if err != nil {
		return nil, err
	}

	row := as.Store.QueryRowx(sql, args...)

	c := &auth.Auth{}
	if err := row.StructScan(c); err != nil {
		return nil, err
	}

	return c, nil
}

// Create ...
func (as *AuthStore) Create(a *auth.Auth) error {
	sql, args, err := squirrel.
		Insert("auth").
		Columns("user_id", "token", "blacklist", "kind").
		Values(a.UserID, a.Token, a.Blacklist, a.Kind).
		Suffix("returning *").
		PlaceholderFormat(squirrel.Dollar).
		ToSql()

	if err != nil {
		return err
	}

	row := as.Store.QueryRowx(sql, args...)
	if err := row.StructScan(a); err != nil {
		return err
	}

	return nil
}

// List ...
func (as *AuthStore) List() ([]*auth.Auth, error) {
	query := squirrel.Select("*").From("auth").Where("deleted_at is null")

	sql, args, err := query.PlaceholderFormat(squirrel.Dollar).ToSql()
	if err != nil {
		return nil, err
	}

	rows, err := as.Store.Queryx(sql, args...)
	if err != nil {
		return nil, err
	}

	aa := make([]*auth.Auth, 0)

	for rows.Next() {
		a := &auth.Auth{}
		if err := rows.StructScan(a); err != nil {
			return nil, err
		}

		aa = append(aa, a)
	}

	return aa, nil
}

// Update ...
func (as *AuthStore) Update(a *auth.Auth) error {
	sql, args, err := squirrel.Update("auth").Set("blacklist", a.Blacklist).Where("id = ?", a.ID).Suffix("returning *").PlaceholderFormat(squirrel.Dollar).ToSql()

	if err != nil {
		return err
	}

	row := as.Store.QueryRowx(sql, args...)
	return row.StructScan(a)
}

// Delete ...
func (as *AuthStore) Delete(a *auth.Auth) error {
	row := as.Store.QueryRowx("update auth set deleted_at = $1 where id = $2 returning *", time.Now(), a.ID)

	if err := row.StructScan(a); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}

	return nil
}
