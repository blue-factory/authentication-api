package client

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/microapis/auth-api"
	authClient "github.com/microapis/auth-api/client"
	users "github.com/microapis/users-api"
)

func before() (string, string, error) {
	host := os.Getenv("HOST")
	if host == "" {
		err := fmt.Errorf(fmt.Sprintf("Create: missing env variable HOST, failed with %s value", host))
		return "", "", err
	}

	port := os.Getenv("PORT")
	if port == "" {
		err := fmt.Errorf(fmt.Sprintf("Create: missing env variable PORT, failed with %s value", port))
		return "", "", err
	}

	return host, port, nil
}

// TestGetByToken ...
func TestGetByToken(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	as, err := authClient.New(host + ":" + port)
	if err != nil {
		log.Fatalln(err)
	}

	randomUUID := uuid.New()

	// After: signup user
	user := &users.User{
		Email:    "fake_email_" + randomUUID.String(),
		Password: "fake_password",
		Name:     "fake_name",
	}

	newUser, err := as.Signup(user)
	if err != nil {
		t.Errorf("TestGetByToken: as.Signup(user) failed: %s", err.Error())
		return
	}

	token := newUser.Meta.Token

	// Test invalid token
	_, err = as.GetByToken(token)
	if err != nil && err.Error() != "invalid token" {
		t.Errorf("TestGetByToken: as.GetByToken() failed: %s", err.Error())
	}

	// Test valid token
	a, err := as.GetByToken(token)
	if err != nil {
		t.Errorf("TestGetByToken: as.Signup(user) failed: %s", err.Error())
		return
	}

	expected := a.UserID
	if expected != newUser.Data.ID {
		t.Errorf("TestGetByToken: a.Data.ID(\"\") failed, expected %v, got %v", expected, user.ID)
		return
	}

	expected = a.ID
	if expected == "" {
		t.Errorf("TestGetByToken: a.ID(\"\") failed, expected %v, got %v", expected, user.ID)
		return
	}

	expected = a.UserID
	if expected == user.ID {
		t.Errorf("TestGetByToken: a.UserID(\"\") failed, expected %v, got %v", expected, user.ID)
		return
	}

	expectedBool := a.Blacklist
	if expectedBool == true {
		t.Errorf("TestGetByToken: a.Blacklist(\"\") failed, expected %v, got %v", expected, false)
		return
	}

	expected = a.Kind
	if expected != auth.KindUser {
		t.Errorf("TestGetByToken: a.Name(\"\") failed, expected %v, got %v", expected, auth.KindForgotPassword)
		return
	}
}

// TestSignup ...
func TestSignup(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	as, err := authClient.New(host + ":" + port)
	if err != nil {
		log.Fatalln(err)
	}

	// Test sign up user with nil value
	_, err = as.Signup(nil)
	if err != nil && err.Error() != "invalid user" {
		t.Errorf("TestSignup: as.Signup() failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: as.Signup() failed: %s", err.Error())
	}

	// Test sign up user with empty values
	user := &users.User{}
	_, err = as.Signup(user)
	if err != nil && err.Error() != "invalid user params" {
		t.Errorf("TestSignup: as.Signup() failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: as.Signup() failed: %s", err.Error())
	}

	// Test create with invalid name new user
	user = &users.User{
		Name: "",
	}
	_, err = as.Signup(user)
	if err != nil && err.Error() != "invalid user params" {
		t.Errorf("TestSignup: as.Signup(user) failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: as.Signup(user) failed: %s", err.Error())
	}

	// Test create invalid email new user
	user = &users.User{
		Name:  "fake_user",
		Email: "",
	}
	_, err = as.Signup(user)
	if err != nil && err.Error() != "invalid user params" {
		t.Errorf("TestSignup: as.Signup(user) failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: as.Signup(user) failed: %s", err.Error())
	}

	randomUUID := uuid.New()

	// Test create invalid password new user
	user = &users.User{
		Name:     "fake_user",
		Email:    "fake_email_" + randomUUID.String(),
		Password: "",
	}
	_, err = as.Signup(user)
	if err != nil && err.Error() != "invalid user params" {
		t.Errorf("TestSignup: as.Signup(user) failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: as.Signup(user) failed: %s", err.Error())
	}

	// Test create valid new user
	user = &users.User{
		Email:    "fake_email_" + randomUUID.String(),
		Password: "fake_password",
		Name:     "fake_name",
	}

	a, err := as.Signup(user)
	if err != nil {
		t.Errorf("TestSignup: as.Signup(user) failed: %s", err.Error())
		return
	}

	expected := a.Data.ID
	if expected == "" {
		t.Errorf("TestSignup: a.Data.ID(\"\") failed, expected %v, got %v", expected, user.ID)
		return
	}

	expected = a.Data.Email
	if user.Email != expected {
		t.Errorf("TestSignup: a.Data.Email(\"\") failed, expected %v, got %v", expected, user.Email)
		return
	}

	expected = a.Data.Password
	if user.Password == expected {
		t.Errorf("TestSignup: a.Data.Password(\"\") failed, expected %v, got %v", expected, user.Password)
		return
	}

	expected = a.Data.Name
	if user.Name != expected {
		t.Errorf("TestSignup: a.Data.Name(\"\") failed, expected %v, got %v", expected, user.Name)
		return
	}

	expected = a.Meta.Token
	if expected == "" {
		t.Errorf("TestSignup: a.Meta.Token(\"\") failed, expected %v", expected)
		return
	}

	// Verify if blacklist is false
	aa, err := as.GetByToken(a.Meta.Token)
	if err != nil {
		t.Errorf("TestGetByToken: as.Signup(user) failed: %s", err.Error())
		return
	}

	expectedBool := aa.Blacklist
	if expectedBool == true {
		t.Errorf("TestSignup: a.Blacklist(\"\") failed, expected %v, got %v", expectedBool, false)
		return
	}

	expected = aa.Kind
	if expected != auth.KindUser {
		t.Errorf("TestSignup: a.Kind(\"\") failed, expected %v, got %v", expected, auth.KindUser)
		return
	}
}

// TestLogin ...
func TestLogin(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	as, err := authClient.New(host + ":" + port)
	if err != nil {
		log.Fatalln(err)
	}

	randomUUID := uuid.New()

	// After: signup user
	user := &users.User{
		Email:    "fake_email_" + randomUUID.String(),
		Password: "fake_password",
		Name:     "fake_name",
	}

	_, err = as.Signup(user)
	if err != nil {
		t.Errorf("TestLogin: as.Signup(user) failed: %s", err.Error())
		return
	}

	// Test login user
	a, err := as.Login(user.Email, user.Password)
	if err != nil {
		t.Errorf("TestLogin: as.Login(user) failed: %s", err.Error())
		return
	}

	expected := a.Data.ID
	if expected == "" {
		t.Errorf("TestLogin: a.Data.ID(\"\") failed, expected %v, got %v", expected, user.ID)
		return
	}

	expected = a.Data.Email
	if user.Email != expected {
		t.Errorf("TestLogin: a.Data.Email(\"\") failed, expected %v, got %v", expected, user.Email)
		return
	}

	expected = a.Data.Password
	if user.Password == expected {
		t.Errorf("TestLogin: a.Data.Password(\"\") failed, expected %v, got %v", expected, user.Password)
		return
	}

	expected = a.Data.Name
	if user.Name != expected {
		t.Errorf("TestLogin: a.Data.Name(\"\") failed, expected %v, got %v", expected, user.Name)
		return
	}

	expected = a.Meta.Token
	if expected == "" {
		t.Errorf("TestLogin: a.Meta.Token(\"\") failed, expected %v", expected)
		return
	}

	// Verify if blacklist is false
	aa, err := as.GetByToken(a.Meta.Token)
	if err != nil {
		t.Errorf("TestGetByToken: as.Signup(user) failed: %s", err.Error())
		return
	}

	expectedBool := aa.Blacklist
	if expectedBool == true {
		t.Errorf("TestSignup: a.Blacklist(\"\") failed, expected %v, got %v", expectedBool, false)
		return
	}

	expected = aa.Kind
	if expected != auth.KindUser {
		t.Errorf("TestSignup: a.Kind(\"\") failed, expected %v, got %v", expected, auth.KindUser)
		return
	}
}

// TestVerifyToken ...
func TestVerifyToken(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	as, err := authClient.New(host + ":" + port)
	if err != nil {
		log.Fatalln(err)
	}

	randomUUID := uuid.New()

	// After: signup user
	user := &users.User{
		Email:    "fake_email_" + randomUUID.String(),
		Password: "fake_password",
		Name:     "fake_name",
	}

	newUser, err := as.Signup(user)
	if err != nil {
		t.Errorf("TestVerifyToken: as.Signup(user) failed: %s", err.Error())
		return
	}

	tt, err := as.VerifyToken(newUser.Meta.Token, auth.KindUser)
	if err != nil {
		t.Errorf("TestVerifyToken: as.VerifyToken(user) failed: %s", err.Error())
	}

	expected := tt.UserID
	if expected != newUser.Data.ID {
		t.Errorf("TestVerifyToken: Token.UserID(\"\") failed, expected %v", expected)
		return
	}

	expectedInt64 := tt.IssuedAt
	if expectedInt64 == 0 {
		t.Errorf("TestVerifyToken: Token.IssuedAt(\"\") failed, expected %v", expectedInt64)
		return
	}

	expectedInt64 = tt.ExpiresAt
	if expectedInt64 == 0 {
		t.Errorf("TestVerifyToken: Token.ExpiresAt(\"\") failed, expected %v", expectedInt64)
		return
	}
}

// TestLogout ...
func TestLogout(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	as, err := authClient.New(host + ":" + port)
	if err != nil {
		log.Fatalln(err)
	}

	randomUUID := uuid.New()

	// After: signup user
	user := &users.User{
		Email:    "fake_email_" + randomUUID.String(),
		Password: "fake_password",
		Name:     "fake_name",
	}

	_, err = as.Signup(user)
	if err != nil {
		t.Errorf("TestLogout: as.Signup(user) failed: %s", err.Error())
		return
	}

	// Login user
	a, err := as.Login(user.Email, user.Password)
	if err != nil {
		t.Errorf("TestLogout: as.Login(user) failed: %s", err.Error())
		return
	}

	// Test invalid token
	err = as.Logout("")
	if err != nil && err.Error() != "invalid token" {
		t.Errorf("TestLogout: as.Logout() failed: %s", err.Error())
	}

	// Test logout user
	err = as.Logout(a.Meta.Token)
	if err != nil {
		t.Errorf("TestLogout: as.Logout(token) failed: %s", err.Error())
		return
	}

	// Verify Token
	_, err = as.VerifyToken(a.Meta.Token, auth.KindUser)
	if err != nil && err.Error() != "token is blacklisted" {
		t.Errorf("TestLogout: as.VerifyToken(token, kind) failed: %s", err.Error())
	}

	// Verify if blacklist is true
	aa, err := as.GetByToken(a.Meta.Token)
	if err != nil {
		t.Errorf("TestLogout: as.GetByToken(user) failed: %s", err.Error())
		return
	}

	expectedBool := aa.Blacklist
	if expectedBool == false {
		t.Errorf("TestLogout: a.Blacklist(\"\") failed, expected %v, got %v", expectedBool, true)
		return
	}

	expected := aa.Kind
	if expected != auth.KindUser {
		t.Errorf("TestLogout: a.Kind(\"\") failed, expected %v, got %v", expected, auth.KindUser)
		return
	}
}

// TestForgotPassword ...
func TestForgotPassword(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	as, err := authClient.New(host + ":" + port)
	if err != nil {
		log.Fatalln(err)
	}

	randomUUID := uuid.New()

	// After: signup user
	user := &users.User{
		Email:    "fake_email_" + randomUUID.String(),
		Password: "fake_password",
		Name:     "fake_name",
	}

	_, err = as.Signup(user)
	if err != nil {
		t.Errorf("TestLogout: as.Signup(user) failed: %s", err.Error())
		return
	}

	_, err = as.ForgotPassword("")
	if err != nil && err.Error() != "invalid email" {
		t.Errorf("TestForgotPassword: as.ForgotPassword(token, kind) failed: %s", err.Error())
	}

	token, err := as.ForgotPassword(user.Email)
	if err != nil {
		t.Errorf("TestForgotPassword: as.ForgotPassword(user) failed: %s", err.Error())
		return
	}

	// Verify if blacklist is false
	aa, err := as.GetByToken(token)
	if err != nil {
		t.Errorf("TestForgotPassword: as.GetByToken(user) failed: %s", err.Error())
		return
	}

	expectedBool := aa.Blacklist
	if expectedBool == true {
		t.Errorf("TestForgotPassword: a.Blacklist(\"\") failed, expected %v, got %v", expectedBool, false)
		return
	}

	expected := aa.Kind
	if expected != auth.KindForgotPassword {
		t.Errorf("TestForgotPassword: a.Kind(\"\") failed, expected %v, got %v", expected, auth.KindForgotPassword)
		return
	}

	// TODO(ca): check if user has sended forgot password email or message
}

// TestRecoverPasssword ...
func TestRecoverPasssword(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	as, err := authClient.New(host + ":" + port)
	if err != nil {
		log.Fatalln(err)
	}

	randomUUID := uuid.New()

	// After: signup user
	user := &users.User{
		Email:    "fake_email_" + randomUUID.String(),
		Password: "fake_password",
		Name:     "fake_name",
	}

	_, err = as.Signup(user)
	if err != nil {
		t.Errorf("TestLogout: as.Signup(user) failed: %s", err.Error())
		return
	}

	token, err := as.ForgotPassword(user.Email)
	if err != nil {
		t.Errorf("TestRecoverPasssword: as.ForgotPassword(user) failed: %s", err.Error())
		return
	}

	newPassword := "new_fake_password"

	err = as.RecoverPassword(newPassword, token)
	if err != nil {
		t.Errorf("TestRecoverPasssword: as.RecoverPassword(newPassword, token) failed: %s", err.Error())
		return
	}

	// TODO(ca): check if user is activated

	// Login user with invalid password
	_, err = as.Login(user.Email, "invalid_new_fake_password")
	if err != nil && err.Error() != "invalid password" {
		t.Errorf("TestRecoverPasssword: as.Login(user) failed: %s", err.Error())
		return
	}

	// Login user with valid password
	_, err = as.Login(user.Email, newPassword)
	if err != nil {
		t.Errorf("TestRecoverPasssword: as.Login(user) failed: %s", err.Error())
		return
	}
}
