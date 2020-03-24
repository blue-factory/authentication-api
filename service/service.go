package service

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"time"

	"github.com/microapis/auth-api"
	"github.com/microapis/auth-api/database"

	"github.com/microapis/users-api"
	uc "github.com/microapis/users-api/client"

	"github.com/dgrijalva/jwt-go"
)

// NewAuth ...
func NewAuth(store database.Store, usersClient *uc.Client) *Auth {
	return &Auth{
		Store:       store,
		UsersClient: usersClient,
	}
}

// Auth ...
type Auth struct {
	Store       database.Store
	UsersClient *uc.Client
}

// GetByToken ...
func (as *Auth) GetByToken(token string) (*auth.Auth, error) {
	// validate token param
	if token == "" {
		return nil, errors.New("invalid token")
	}

	// get Auth by token from store
	a, err := as.Store.Get(&auth.Query{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	return a, nil
}

// Login ...
func (as *Auth) Login(email, password string) (*auth.Response, error) {
	// validate email param
	if email == "" {
		return nil, errors.New("invalid email")
	}

	// validate password param
	if password == "" {
		return nil, errors.New("invalid password")
	}

	// verify if password is valid
	err := as.UsersClient.VerifyPassword(email, password)
	if err != nil {
		return nil, err
	}

	// get user by email
	user, err := as.UsersClient.GetByEmail(email)
	if err != nil {
		return nil, err
	}

	// create token difinition
	t := auth.Token{
		UserID: user.ID,
		StandardClaims: &jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(8760 * time.Hour).UnixNano(), // one year of expiration
		},
	}

	// get jwt secret env value
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("env variable JWT_SECRET must be defined")
	}

	// generate jwt token
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), t)
	tokenStr, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return nil, err
	}

	// create auth definition
	a := &auth.Auth{
		Token:     tokenStr,
		Kind:      auth.KindUser,
		Blacklist: false,
		UserID:    user.ID,
	}

	// save auth store
	err = as.Store.Create(a)
	if err != nil {
		return nil, err
	}

	// prepare metatoken
	mt := &auth.MetaToken{
		Token: tokenStr,
	}

	// prepare response
	res := &auth.Response{
		Data: user,
		Meta: mt,
	}

	return res, nil
}

// Signup ...
func (as *Auth) Signup(u *users.User) (*auth.Response, error) {
	// validate user existence
	if u == nil {
		return nil, errors.New("invalid user")
	}

	// validate user params
	if u.Name == "" || u.Email == "" || u.Password == "" {
		return nil, errors.New("invalid user params")
	}

	// create new user
	user, err := as.UsersClient.Create(u)
	if err != nil {
		return nil, err
	}

	// create token definition
	t := auth.Token{
		UserID: user.ID,
		StandardClaims: &jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(8760 * time.Hour).UnixNano(), // one year of expiration
		},
	}

	// get jwt secret env value
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("env variable JWT_SECRET must be defined")
	}

	// generate jwt token
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), t)
	tokenStr, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return nil, err
	}

	// create auth definition
	a := &auth.Auth{
		Token:     tokenStr,
		Kind:      auth.KindUser,
		Blacklist: false,
		UserID:    user.ID,
	}

	// save auth store
	err = as.Store.Create(a)
	if err != nil {
		return nil, err
	}

	// prepare metatoken
	mt := &auth.MetaToken{
		Token: tokenStr,
	}

	// prepare response
	res := &auth.Response{
		Data: user,
		Meta: mt,
	}

	return res, nil
}

// VerifyToken ...
func (as *Auth) VerifyToken(token string, kind string) (*auth.Token, error) {
	// validate token param
	if token == "" {
		return nil, errors.New("invalid token")
	}

	// validate kind param
	if kind == "" {
		return nil, errors.New("invalid kind")
	}

	// get Auth by token from store
	a, err := as.Store.Get(&auth.Query{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	// validate auth kind
	if a.Kind != kind {
		return nil, errors.New("invalid kind")
	}

	// check if token is blacklisted
	if a.Blacklist {
		return nil, errors.New("token is blacklisted")
	}

	// get jwt secret env value
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("env variable JWT_SECRET must be defined")
	}

	// decode token
	// validate token is valid with JWT_SECRET
	// validate token is not expired
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return nil, err
	}

	// parser map to struct
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	decode := new(auth.Token)
	err = json.Unmarshal(data, decode)
	if err != nil {
		return nil, err
	}

	return decode, nil
}

// Logout ...
func (as *Auth) Logout(token string) error {
	// validate token param
	if token == "" {
		return errors.New("invalid token")
	}

	// get Auth by token from store
	a, err := as.Store.Get(&auth.Query{
		Token: token,
	})
	if err != nil {
		return err
	}

	// check if token is blacklisted
	if a.Blacklist {
		return errors.New("token is blacklisted")
	}

	// validate auth kind is user
	if a.Kind != auth.KindUser {
		return errors.New("invalid auth kind")
	}

	// get jwt secret env value
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("Env variable JWT_SECRET must be defined")
	}

	// decode token
	// validate token is valid with JWT_SECRET
	// validate token is not expired
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return err
	}

	// parser map to struct
	data, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	var decode auth.Token
	err = json.Unmarshal(data, &decode)
	if err != nil {
		return err
	}

	// update blacklist to true
	a.Blacklist = true
	err = as.Store.Update(a)
	if err != nil {
		return err
	}

	return nil
}

// ForgotPassword ...
func (as *Auth) ForgotPassword(email string) (string, error) {
	// validate email param
	if email == "" {
		return "", errors.New("invalid email")
	}

	// check if email exist on users service
	user, err := as.UsersClient.GetByEmail(email)
	if err != nil {
		return "", err
	}

	// create temporal token difinition
	t := auth.Token{
		UserID: user.ID,
		StandardClaims: &jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(5 * time.Minute).UnixNano(), // five minutes of expiration
		},
	}

	// get jwt secret env value
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("Env variable JWT_SECRET must be defined")
	}

	// generate jwt token
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), t)
	tokenStr, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	// create auth definition
	a := &auth.Auth{
		Token:     tokenStr,
		Kind:      auth.KindForgotPassword,
		Blacklist: false,
		UserID:    user.ID,
	}

	// save auth store
	err = as.Store.Create(a)
	if err != nil {
		return "", err
	}

	// TODO(ca): send email with token and url

	return tokenStr, nil
}

// RecoverPassword ...
func (as *Auth) RecoverPassword(newPassword, token string) error {
	// validate newPassword param
	if newPassword == "" {
		return errors.New("invalid newPassword")
	}

	// validate token param
	if token == "" {
		return errors.New("invalid token")
	}

	// get Auth by token from store
	a, err := as.Store.Get(&auth.Query{
		Token: token,
	})
	if err != nil {
		return err
	}

	// check if token is blacklisted
	if a.Blacklist {
		return errors.New("token is blacklisted")
	}

	// validate auth kind is forgot-password
	if a.Kind != auth.KindForgotPassword {
		return errors.New("invalid auth kind")
	}

	// get jwt secret env value
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("Env variable JWT_SECRET must be defined")
	}

	// decode token
	// validate token is valid with JWT_SECRET
	// validate token is not expired
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return err
	}

	// parser map to struct
	data, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	var decode auth.Token
	err = json.Unmarshal(data, &decode)
	if err != nil {
		return err
	}

	// update user password
	_, err = as.UsersClient.Update(decode.UserID, &users.User{
		Password: newPassword,
	})
	if err != nil {
		return err
	}

	// update blacklist to true
	a.Blacklist = true
	err = as.Store.Update(a)
	if err != nil {
		return err
	}

	return nil
}
