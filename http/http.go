package http

import (
	"github.com/gorilla/mux"
	ac "github.com/microapis/auth-api/client"
)

// Response ...
type Response struct {
	Data  interface{} `json:"data,omitempty"`
	Meta  interface{} `json:"meta,omitempty"`
	Error interface{} `json:"error,omitempty"`
}

type handlerContext struct {
	AuthClient *ac.Client
}

// New ...
func New(ac *ac.Client) *mux.Router {
	r := mux.NewRouter()
	s := r.PathPrefix("/api/v1/auth").Subrouter()

	// define context
	ctx := handlerContext{
		AuthClient: ac,
	}

	// GET /api/v1/auth/token/:id
	s.HandleFunc("/token/{id}", GetByToken(ctx)).Methods("GET")

	// POST /api/v1/auth/login
	s.HandleFunc("/login", Login(ctx)).Methods("POST")

	// POST /api/v1/auth
	s.HandleFunc("/signup", Signup(ctx)).Methods("POST")

	// POST /api/v1/verify-token
	s.HandleFunc("/verify-token", VerifyToken(ctx)).Methods("POST")

	// POST /api/v1/auth/verify-email
	s.HandleFunc("/verify-email", VerifyEmail(ctx)).Methods("POST")

	// POST /api/v1/auth/logout
	s.HandleFunc("/logout", Logout(ctx)).Methods("POST")

	// POST /api/v1/auth/forgot-password
	s.HandleFunc("/forgot-password", ForgotPassword(ctx)).Methods("POST")

	// POST /api/v1/auth/recover-password
	s.HandleFunc("/recover-password", RecoverPassword(ctx)).Methods("POST")

	return s
}
