package auth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	pb "github.com/microapis/auth-api/proto"
	users "github.com/microapis/users-api"
)

const (
	// KindUser ...
	KindUser = "user"
	// KindForgotPassword ...
	KindForgotPassword = "forgot-password"
	// KindVerifyPassword ...
	KindVerifyPassword = "verify-password"
)

// Token ...
type Token struct {
	UserID string `json:"user_id"`
	*jwt.StandardClaims
}

// ToProto ...
func (t *Token) ToProto() *pb.AuthToken {
	return &pb.AuthToken{
		Iat:    t.IssuedAt,
		Exp:    t.ExpiresAt,
		UserId: t.UserID,
	}
}

// FromProto ...
func (t *Token) FromProto(tt *pb.AuthToken) *Token {
	sc := &jwt.StandardClaims{
		IssuedAt:  tt.GetIat(),
		ExpiresAt: tt.GetExp(),
	}

	t.UserID = tt.GetUserId()
	t.StandardClaims = sc

	return t
}

// Auth ...
type Auth struct {
	ID string `json:"id" db:"id"`

	UserID    string `json:"user_id" db:"user_id"`
	Token     string `json:"token" db:"token"`
	Blacklist bool   `json:"blacklist" db:"blacklist"`
	Kind      string `json:"kind" db:"kind"` // user, forgot-password

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"-" db:"deleted_at"`
}

// ToProto ...
func (t *Auth) ToProto() *pb.Auth {
	return &pb.Auth{
		Id:        t.ID,
		UserId:    t.UserID,
		Token:     t.Token,
		Blacklist: t.Blacklist,
		Kind:      t.Kind,
		CreatedAt: t.CreatedAt.UnixNano(),
		UpdatedAt: t.CreatedAt.UnixNano(),
	}
}

// FromProto ...
func (t *Auth) FromProto(tt *pb.Auth) *Auth {
	t.ID = tt.GetId()

	t.UserID = tt.GetUserId()
	t.Token = tt.GetToken()
	t.Blacklist = tt.GetBlacklist()
	t.Kind = tt.GetKind()

	t.CreatedAt = time.Unix(tt.CreatedAt, 0)
	t.UpdatedAt = time.Unix(tt.UpdatedAt, 0)

	return t
}

// Response ...
type Response struct {
	Data *users.User `json:"data"`
	Meta *MetaToken  `json:"meta"`
}

// MetaToken ...
type MetaToken struct {
	Token             string `json:"token"`
	VerificationToken string `json:"verification_token,omitempty"`
}

// Service ...
type Service interface {
	GetByToken(token string) (*Auth, error)
	Login(email, password string) (*Response, error)
	Signup(user *users.User) (*Response, error)
	VerifyToken(token string, kind string) (*Token, error)
	VerifyEmail(token string) error
	Logout(token string) error
	ForgotPassword(email string) (string, error)
	RecoverPassword(newPassword, token string) error
}

// Query ...
type Query struct {
	Token  string
	Email  string
	UserID string
}
