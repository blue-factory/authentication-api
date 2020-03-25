package auth

import (
	"context"
	"fmt"

	"github.com/microapis/users-api"

	"github.com/microapis/auth-api"
	"github.com/microapis/auth-api/database"
	pb "github.com/microapis/auth-api/proto"
	"github.com/microapis/auth-api/service"

	e "github.com/microapis/email-api/client"
	u "github.com/microapis/users-api/client"
)

var _ pb.AuthServiceServer = (*Service)(nil)

// Service ...
type Service struct {
	AuthSvc auth.Service
}

// New ...
func New(store database.Store, uc *u.Client, ec *e.Client) *Service {
	return &Service{
		AuthSvc: service.NewAuth(store, uc, ec),
	}
}

// GetByToken ...
func (s *Service) GetByToken(ctx context.Context, gr *pb.AuthGetByTokenRequest) (*pb.AuthGetByTokenResponse, error) {
	token := gr.GetToken()
	fmt.Println(fmt.Sprintf("[gRPC][Auth][GetByToken][Request] token = %v", token))

	// get and validate token param
	if token == "" {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][GetByToken][Error] %v", "invalid token"))
		return &pb.AuthGetByTokenResponse{
			Error: &pb.AuthError{
				Code:    500,
				Message: "invalid token",
			},
		}, nil
	}

	// get auth by token
	auth, err := s.AuthSvc.GetByToken(token)
	if err != nil {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][GetByToken][Error] %v", err))
		return &pb.AuthGetByTokenResponse{
			Error: &pb.AuthError{
				Code:    500,
				Message: err.Error(),
			},
		}, nil
	}

	res := &pb.AuthGetByTokenResponse{
		Data: auth.ToProto(),
	}

	fmt.Println(fmt.Sprintf("[gRPC][Auth][GetByToken][Response] %v", res))
	return res, nil
}

// Login ...
func (s *Service) Login(ctx context.Context, gr *pb.AuthLoginRequest) (*pb.AuthLoginResponse, error) {
	email := gr.GetEmail()
	password := gr.GetPassword()
	fmt.Println(fmt.Sprintf("[gRPC][Auth][Login][Request] email = %v password = %v", email, password))

	// get and validate email and password params
	if email == "" || password == "" {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][Login][Error] %v", "invalid email or password"))
		return &pb.AuthLoginResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: "invalid email or password",
			},
		}, nil
	}

	// login with email and password on users-api
	auth, err := s.AuthSvc.Login(email, password)
	if err != nil {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][Login][Error] %v", err))
		return &pb.AuthLoginResponse{
			Error: &pb.AuthError{
				Code:    500,
				Message: err.Error(),
			},
		}, nil
	}

	res := &pb.AuthLoginResponse{
		Data: auth.Data.ToProto(),
		Meta: &pb.AuthMetaToken{
			Token: auth.Meta.Token,
		},
	}

	fmt.Println(fmt.Sprintf("[gRPC][Auth][Login][Response] %v", res))
	return res, nil
}

// Signup ...
func (s *Service) Signup(ctx context.Context, gr *pb.AuthSignupRequest) (*pb.AuthSignupResponse, error) {
	data := gr.GetUser()
	fmt.Println(fmt.Sprintf("[gRPC][Auth][Signup][Request] user = %v", data))

	// get and validate user param
	if data == nil {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][Signup][Error] %v", "invalid user"))
		return &pb.AuthSignupResponse{
			Error: &pb.AuthError{
				Code:    500,
				Message: "invalid user",
			},
		}, nil
	}

	// get user params
	email := data.GetEmail()
	name := data.GetName()
	password := data.GetPassword()

	// validate user params
	if email == "" || name == "" || password == "" {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][Signup][Error] %v", "invalid user params"))
		return &pb.AuthSignupResponse{
			Error: &pb.AuthError{
				Code:    500,
				Message: "invalid user params",
			},
		}, nil
	}

	// create user definition
	user := &users.User{
		Email:    email,
		Name:     name,
		Password: password,
	}

	// signup created user
	res, err := s.AuthSvc.Signup(user)
	if err != nil {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][Signup][Error] %v", err))
		return &pb.AuthSignupResponse{
			Error: &pb.AuthError{
				Code:    500,
				Message: err.Error(),
			},
		}, nil
	}

	r := &pb.AuthSignupResponse{
		Data: res.Data.ToProto(),
		Meta: &pb.AuthMetaToken{
			Token: res.Meta.Token,
		},
	}

	fmt.Println(fmt.Sprintf("[gRPC][Auth][Signup][Response] %v", r))
	return r, nil
}

// VerifyToken ...
func (s *Service) VerifyToken(ctx context.Context, gr *pb.AuthVerifyTokenRequest) (*pb.AuthVerifyTokenResponse, error) {
	token := gr.GetToken()
	kind := gr.GetKind()
	fmt.Println(fmt.Sprintf("[gRPC][Auth][VerifyToken][Request] token = %v kind = %v", token, kind))

	// get and validate token and kind params
	if token == "" || kind == "" {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][VerifyToken][Error] %v", "invalid token or kind"))
		return &pb.AuthVerifyTokenResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: "invalid token or kind",
			},
		}, nil
	}

	t, err := s.AuthSvc.VerifyToken(token, kind)
	if err != nil {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][VerifyToken][Error] %v", err))
		return &pb.AuthVerifyTokenResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: err.Error(),
			},
		}, nil
	}

	res := &pb.AuthVerifyTokenResponse{
		Data: t.ToProto(),
	}

	fmt.Println(fmt.Sprintf("[gRPC][Auth][VerifyToken][Response] %v", res))
	return res, nil
}

// Logout ...
func (s *Service) Logout(ctx context.Context, gr *pb.AuthLogoutRequest) (*pb.AuthLogoutResponse, error) {
	token := gr.GetToken()
	fmt.Println(fmt.Sprintf("[gRPC][Auth][Logout][Request] token = %v", token))

	// get and validate token param
	if token == "" {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][Logout][Error] %v", "invalid token"))
		return &pb.AuthLogoutResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: "invalid token",
			},
		}, nil
	}

	err := s.AuthSvc.Logout(token)
	if err != nil {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][Logout][Error] %v", err))
		return &pb.AuthLogoutResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: err.Error(),
			},
		}, nil
	}

	res := &pb.AuthLogoutResponse{}

	fmt.Println(fmt.Sprintf("[gRPC][Auth][Logout][Response] %v", res))
	return res, nil
}

// ForgotPassword ...
func (s *Service) ForgotPassword(ctx context.Context, gr *pb.AuthForgotPasswordRequest) (*pb.AuthForgotPasswordResponse, error) {
	email := gr.GetEmail()
	fmt.Println(fmt.Sprintf("[gRPC][Auth][ForgotPassword][Request] email = %v", email))

	// get and validate email param
	if email == "" {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][ForgotPassword][Error] %v", "invalid email"))
		return &pb.AuthForgotPasswordResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: "invalid email",
			},
		}, nil
	}

	token, err := s.AuthSvc.ForgotPassword(email)
	if err != nil {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][ForgotPassword][Error] %v", err))
		return &pb.AuthForgotPasswordResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: err.Error(),
			},
		}, nil
	}

	res := &pb.AuthForgotPasswordResponse{
		Data: &pb.AuthMetaToken{
			Token: token,
		},
	}

	fmt.Println(fmt.Sprintf("[gRPC][Auth][ForgotPassword][Response] %v", res))
	return res, nil
}

// RecoverPassword ...
func (s *Service) RecoverPassword(ctx context.Context, gr *pb.AuthRecoverPasswordRequest) (*pb.AuthRecoverPasswordResponse, error) {
	newPassword := gr.GetNewPassword()
	token := gr.GetToken()
	fmt.Println(fmt.Sprintf("[gRPC][Auth][RecoverPassword][Request] newPassword = %v token = %v", newPassword, token))

	// get and validate token and newPassword params
	if newPassword == "" || token == "" {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][RecoverPassword][Error] %v", "invalid newPassword or token"))
		return &pb.AuthRecoverPasswordResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: "invalid newPassword or token",
			},
		}, nil
	}

	err := s.AuthSvc.RecoverPassword(newPassword, token)
	if err != nil {
		fmt.Println(fmt.Sprintf("[gRPC][Auth][RecoverPassword][Error] %v", err))
		return &pb.AuthRecoverPasswordResponse{
			Error: &pb.AuthError{
				Code:    401,
				Message: err.Error(),
			},
		}, nil
	}

	res := &pb.AuthRecoverPasswordResponse{}

	fmt.Println(fmt.Sprintf("[gRPC][Auth][RecoverPassword][Response] %v", res))
	return res, nil
}
