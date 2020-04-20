package authclient_test

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/google/uuid"

	auth "github.com/microapis/authentication-api"
	authclient "github.com/microapis/authentication-api/client"
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

	client, err := authclient.New(host + ":" + port)
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

	newUser, err := client.Signup(user)
	if err != nil {
		t.Errorf("TestGetByToken: client.Signup(user) failed: %s", err.Error())
		return
	}

	token := newUser.Meta.Token

	// Test invalid token
	_, err = client.GetByToken(token)
	if err != nil && err.Error() != "invalid token" {
		t.Errorf("TestGetByToken: client.GetByToken() failed: %s", err.Error())
	}

	// Test valid token
	a, err := client.GetByToken(token)
	if err != nil {
		t.Errorf("TestGetByToken: client.Signup(user) failed: %s", err.Error())
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

	client, err := authclient.New(host + ":" + port)
	if err != nil {
		log.Fatalln(err)
	}

	// Test sign up user with nil value
	_, err = client.Signup(nil)
	if err != nil && err.Error() != "invalid user" {
		t.Errorf("TestSignup: client.Signup() failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: client.Signup() failed: %s", err.Error())
	}

	// Test sign up user with empty values
	user := &users.User{}
	_, err = client.Signup(user)
	if err != nil && err.Error() != "invalid user params" {
		t.Errorf("TestSignup: client.Signup() failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: client.Signup() failed: %s", err.Error())
	}

	// Test create with invalid name new user
	user = &users.User{
		Name: "",
	}
	_, err = client.Signup(user)
	if err != nil && err.Error() != "invalid user params" {
		t.Errorf("TestSignup: client.Signup(user) failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: client.Signup(user) failed: %s", err.Error())
	}

	// Test create invalid email new user
	user = &users.User{
		Name:  "fake_user",
		Email: "",
	}
	_, err = client.Signup(user)
	if err != nil && err.Error() != "invalid user params" {
		t.Errorf("TestSignup: client.Signup(user) failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: client.Signup(user) failed: %s", err.Error())
	}

	randomUUID := uuid.New()

	// Test create invalid password new user
	user = &users.User{
		Name:     "fake_user",
		Email:    "fake_email_" + randomUUID.String(),
		Password: "",
	}
	_, err = client.Signup(user)
	if err != nil && err.Error() != "invalid user params" {
		t.Errorf("TestSignup: client.Signup(user) failed: %s", err.Error())
	}
	if err == nil {
		t.Errorf("TestSignup: client.Signup(user) failed: %s", err.Error())
	}

	// Test create valid new user
	user = &users.User{
		Email:    "fake_email_" + randomUUID.String(),
		Password: "fake_password",
		Name:     "fake_name",
	}

	a, err := client.Signup(user)
	if err != nil {
		t.Errorf("TestSignup: client.Signup(user) failed: %s", err.Error())
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

	expectedBool := a.Data.Verified
	if user.Verified != expectedBool {
		t.Errorf("TestSignup: a.Data.Verified(\"\") failed, expected %v, got %v", expectedBool, user.Name)
		return
	}

	expected = a.Meta.Token
	if expected == "" {
		t.Errorf("TestSignup: a.Meta.Token(\"\") failed, expected %v", expected)
		return
	}

	expected = a.Meta.VerificationToken
	if expected == "" {
		t.Errorf("TestSignup: a.Meta.VerificationToken(\"\") failed, expected %v", expected)
		return
	}

	// Verify if blacklist is false
	aa, err := client.GetByToken(a.Meta.Token)
	if err != nil {
		t.Errorf("TestGetByToken: client.Signup(user) failed: %s", err.Error())
		return
	}

	expectedBool = aa.Blacklist
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

	client, err := authclient.New(host + ":" + port)
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

	_, err = client.Signup(user)
	if err != nil {
		t.Errorf("TestLogin: client.Signup(user) failed: %s", err.Error())
		return
	}

	// Test login user
	a, err := client.Login(user.Email, user.Password)
	if err != nil {
		t.Errorf("TestLogin: client.Login(user) failed: %s", err.Error())
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

	expectedBool := a.Data.Verified
	if user.Verified != expectedBool {
		t.Errorf("TestLogin: a.Data.Verified(\"\") failed, expected %v, got %v", expectedBool, user.Name)
		return
	}

	expected = a.Meta.Token
	if expected == "" {
		t.Errorf("TestLogin: a.Meta.Token(\"\") failed, expected %v", expected)
		return
	}

	expected = a.Meta.VerificationToken
	if expected != "" {
		t.Errorf("TestLogin: a.Meta.VerificationToken(\"\") failed, expected %v", expected)
		return
	}

	// Verify if blacklist is false
	aa, err := client.GetByToken(a.Meta.Token)
	if err != nil {
		t.Errorf("TestLogin: client.GetByToken(user) failed: %s", err.Error())
		return
	}

	expectedBool = aa.Blacklist
	if expectedBool == true {
		t.Errorf("TestLogin: a.Blacklist(\"\") failed, expected %v, got %v", expectedBool, false)
		return
	}

	expected = aa.Kind
	if expected != auth.KindUser {
		t.Errorf("TestLogin: a.Kind(\"\") failed, expected %v, got %v", expected, auth.KindUser)
		return
	}
}

// TestVerifyToken ...
func TestVerifyToken(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	client, err := authclient.New(host + ":" + port)
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

	newUser, err := client.Signup(user)
	if err != nil {
		t.Errorf("TestVerifyToken: client.Signup(user) failed: %s", err.Error())
		return
	}

	tt, err := client.VerifyToken(newUser.Meta.Token, auth.KindUser)
	if err != nil {
		t.Errorf("TestVerifyToken: client.VerifyToken(user) failed: %s", err.Error())
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

// TestVerifyEmail ...
func TestVerifyEmail(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	client, err := authclient.New(host + ":" + port)
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

	newUser, err := client.Signup(user)
	if err != nil {
		t.Errorf("TestVerifyEmail: client.Signup(user) failed: %s", err.Error())
		return
	}

	vt := newUser.Meta.VerificationToken

	// Test valid token
	a, err := client.GetByToken(vt)
	if err != nil {
		t.Errorf("TestVerifyEmail: client.Signup(user) failed: %s", err.Error())
		return
	}

	expected := a.ID
	if expected == "" {
		t.Errorf("TestVerifyEmail: a.ID(\"\") failed, expected %v, got %v", expected, user.ID)
		return
	}

	expected = a.UserID
	if expected == user.ID {
		t.Errorf("TestVerifyEmail: a.UserID(\"\") failed, expected %v, got %v", expected, user.ID)
		return
	}

	expectedBool := a.Blacklist
	if expectedBool == true {
		t.Errorf("TestVerifyEmail: a.Blacklist(\"\") failed, expected %v, got %v", expected, false)
		return
	}

	expected = a.Kind
	if expected != auth.KindVerifyPassword {
		t.Errorf("TestVerifyEmail: a.Kind(\"\") failed, expected %v, got %v", expected, auth.KindVerifyPassword)
		return
	}

	// Verify email
	err = client.VerifyEmail(vt)
	if err != nil {
		t.Errorf("TestVerifyEmail: client.VerifyEmail(user) failed: %s", err.Error())
		return
	}

	// Login user
	aa, err := client.Login(user.Email, user.Password)
	if err != nil {
		t.Errorf("TestVerifyEmail: client.Login(user) failed: %s", err.Error())
		return
	}

	expected = aa.Data.ID
	if expected == "" {
		t.Errorf("TestVerifyEmail: aa.Data.ID(\"\") failed, expected %v, got %v", expected, user.ID)
		return
	}

	expected = aa.Data.Email
	if user.Email != expected {
		t.Errorf("TestVerifyEmail: aa.Data.Email(\"\") failed, expected %v, got %v", expected, user.Email)
		return
	}

	expected = aa.Data.Password
	if user.Password == expected {
		t.Errorf("TestVerifyEmail: aa.Data.Password(\"\") failed, expected %v, got %v", expected, user.Password)
		return
	}

	expected = aa.Data.Name
	if user.Name != expected {
		t.Errorf("TestVerifyEmail: aa.Data.Name(\"\") failed, expected %v, got %v", expected, user.Name)
		return
	}

	expectedBool = aa.Data.Verified
	if true != expectedBool {
		t.Errorf("TestVerifyEmail: aa.Data.Verified(\"\") failed, expected %v, got %v", expectedBool, true)
		return
	}

	expected = aa.Meta.Token
	if expected == "" {
		t.Errorf("TestVerifyEmail: aa.Meta.Token(\"\") failed, expected %v", expected)
		return
	}

	expected = aa.Meta.VerificationToken
	if expected != "" {
		t.Errorf("TestVerifyEmail: aa.Meta.VerificationToken(\"\") failed, expected %v", expected)
		return
	}
}

// TestLogout ...
func TestLogout(t *testing.T) {
	host, port, err := before()
	if err != nil {
		t.Errorf(err.Error())
	}

	client, err := authclient.New(host + ":" + port)
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

	_, err = client.Signup(user)
	if err != nil {
		t.Errorf("TestLogout: client.Signup(user) failed: %s", err.Error())
		return
	}

	// Login user
	a, err := client.Login(user.Email, user.Password)
	if err != nil {
		t.Errorf("TestLogout: client.Login(user) failed: %s", err.Error())
		return
	}

	// Test invalid token
	err = client.Logout("")
	if err != nil && err.Error() != "invalid token" {
		t.Errorf("TestLogout: client.Logout() failed: %s", err.Error())
	}

	// Test logout user
	err = client.Logout(a.Meta.Token)
	if err != nil {
		t.Errorf("TestLogout: client.Logout(token) failed: %s", err.Error())
		return
	}

	// Verify Token
	_, err = client.VerifyToken(a.Meta.Token, auth.KindUser)
	if err != nil && err.Error() != "token is blacklisted" {
		t.Errorf("TestLogout: client.VerifyToken(token, kind) failed: %s", err.Error())
	}

	// Verify if blacklist is true
	aa, err := client.GetByToken(a.Meta.Token)
	if err != nil {
		t.Errorf("TestLogout: client.GetByToken(user) failed: %s", err.Error())
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

	client, err := authclient.New(host + ":" + port)
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

	_, err = client.Signup(user)
	if err != nil {
		t.Errorf("TestLogout: client.Signup(user) failed: %s", err.Error())
		return
	}

	_, err = client.ForgotPassword("")
	if err != nil && err.Error() != "invalid email" {
		t.Errorf("TestForgotPassword: client.ForgotPassword(token, kind) failed: %s", err.Error())
	}

	token, err := client.ForgotPassword(user.Email)
	if err != nil {
		t.Errorf("TestForgotPassword: client.ForgotPassword(user) failed: %s", err.Error())
		return
	}

	// Verify if blacklist is false
	aa, err := client.GetByToken(token)
	if err != nil {
		t.Errorf("TestForgotPassword: client.GetByToken(user) failed: %s", err.Error())
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

	client, err := authclient.New(host + ":" + port)
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

	_, err = client.Signup(user)
	if err != nil {
		t.Errorf("TestLogout: client.Signup(user) failed: %s", err.Error())
		return
	}

	token, err := client.ForgotPassword(user.Email)
	if err != nil {
		t.Errorf("TestRecoverPasssword: client.ForgotPassword(user) failed: %s", err.Error())
		return
	}

	newPassword := "new_fake_password"

	err = client.RecoverPassword(newPassword, token)
	if err != nil {
		t.Errorf("TestRecoverPasssword: client.RecoverPassword(newPassword, token) failed: %s", err.Error())
		return
	}

	// TODO(ca): check if user is activated

	// Login user with invalid password
	_, err = client.Login(user.Email, "invalid_new_fake_password")
	if err != nil && err.Error() != "invalid password" {
		t.Errorf("TestRecoverPasssword: client.Login(user) failed: %s", err.Error())
		return
	}

	// Login user with valid password
	_, err = client.Login(user.Email, newPassword)
	if err != nil {
		t.Errorf("TestRecoverPasssword: client.Login(user) failed: %s", err.Error())
		return
	}
}
