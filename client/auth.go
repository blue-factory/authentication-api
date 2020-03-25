package client

import (
	"context"
	"errors"

	"github.com/microapis/auth-api"
	pb "github.com/microapis/auth-api/proto"
	users "github.com/microapis/users-api"
	"google.golang.org/grpc"
)

// Client ...
type Client struct {
	Client pb.AuthServiceClient
}

// New ...
func New(address string) (*Client, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	c := pb.NewAuthServiceClient(conn)

	return &Client{
		Client: c,
	}, nil
}

// GetByToken ...
func (c *Client) GetByToken(token string) (*auth.Auth, error) {
	// validate token param
	if token == "" {
		return nil, errors.New("invalid token")
	}

	gr, err := c.Client.GetByToken(context.Background(), &pb.AuthGetByTokenRequest{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	msg := gr.GetError().GetMessage()
	if msg != "" {
		return nil, errors.New(msg)
	}

	a := gr.GetData()
	aa := &auth.Auth{}

	return aa.FromProto(a), nil
}

// Login ...
func (c *Client) Login(email string, password string) (*auth.Response, error) {
	// validate email param
	if email == "" {
		return nil, errors.New("invalid email")
	}

	// validate password param
	if password == "" {
		return nil, errors.New("invalid password")
	}

	gr, err := c.Client.Login(context.Background(), &pb.AuthLoginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		return nil, err
	}

	msg := gr.GetError().GetMessage()
	if msg != "" {
		return nil, errors.New(msg)
	}

	data := gr.GetData()
	token := gr.GetMeta().GetToken()

	u := &users.User{}
	r := &auth.Response{
		Data: u.FromProto(data),
		Meta: &auth.MetaToken{
			Token: token,
		},
	}

	return r, nil
}

// Signup ...
func (c *Client) Signup(u *users.User) (*auth.Response, error) {
	// validate user existence
	if u == nil {
		return nil, errors.New("invalid user")
	}

	// validate user params
	if u.Name == "" || u.Email == "" || u.Password == "" {
		return nil, errors.New("invalid user params")
	}

	gr, err := c.Client.Signup(context.Background(), &pb.AuthSignupRequest{
		User: u.ToProto(),
	})
	if err != nil {
		return nil, err
	}

	msg := gr.GetError().GetMessage()
	if msg != "" {
		return nil, errors.New(msg)
	}

	data := gr.GetData()
	token := gr.GetMeta().GetToken()

	uu := &users.User{}
	r := &auth.Response{
		Data: uu.FromProto(data),
		Meta: &auth.MetaToken{
			Token: token,
		},
	}

	return r, nil
}

// VerifyToken ...
func (c *Client) VerifyToken(token string, kind string) (*auth.Token, error) {
	// validate token param
	if token == "" {
		return nil, errors.New("invalid token")
	}

	// validate kind param
	if kind == "" {
		return nil, errors.New("invalid kind")
	}

	gr, err := c.Client.VerifyToken(context.Background(), &pb.AuthVerifyTokenRequest{
		Token: token,
		Kind:  kind,
	})
	if err != nil {
		return nil, err
	}

	msg := gr.GetError().GetMessage()
	if msg != "" {
		return nil, errors.New(msg)
	}

	t := gr.GetData()
	tt := &auth.Token{}

	return tt.FromProto(t), nil
}

// Logout ...
func (c *Client) Logout(token string) error {
	// validate token param
	if token == "" {
		return errors.New("invalid token")
	}

	gr, err := c.Client.Logout(context.Background(), &pb.AuthLogoutRequest{
		Token: token,
	})
	if err != nil {
		return err
	}

	msg := gr.GetError().GetMessage()
	if msg != "" {
		return errors.New(msg)
	}

	return nil
}

// ForgotPassword ...
func (c *Client) ForgotPassword(email string) (string, error) {
	// validate email param
	if email == "" {
		return "", errors.New("invalid email")
	}

	gr, err := c.Client.ForgotPassword(context.Background(), &pb.AuthForgotPasswordRequest{
		Email: email,
	})
	if err != nil {
		return "", err
	}

	msg := gr.GetError().GetMessage()
	if msg != "" {
		return "", errors.New(msg)
	}

	data := gr.GetData()
	token := data.GetToken()

	return token, nil
}

// RecoverPassword ...
func (c *Client) RecoverPassword(newPassword string, token string) error {
	// validate newPassword param
	if newPassword == "" {
		return errors.New("invalid newPassword")
	}

	// validate token param
	if token == "" {
		return errors.New("invalid token")
	}

	gr, err := c.Client.RecoverPassword(context.Background(), &pb.AuthRecoverPasswordRequest{
		NewPassword: newPassword,
		Token:       token,
	})
	if err != nil {
		return err
	}

	msg := gr.GetError().GetMessage()
	if msg != "" {
		return errors.New(msg)
	}

	return nil
}
