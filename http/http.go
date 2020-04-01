package http

import (
	h "net/http"

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

// Routes ...
func Routes(r *mux.Router, ac *ac.Client) {
	s := r.PathPrefix("/api/v1/auth").Subrouter()

	// define context
	ctx := handlerContext{
		AuthClient: ac,
	}

	// POST /api/v1/auth/login
	s.HandleFunc("/login", login(ctx)).Methods(h.MethodPost, h.MethodOptions)

	// POST /api/v1/auth
	s.HandleFunc("/signup", signup(ctx)).Methods(h.MethodPost, h.MethodOptions)

	// POST /api/v1/verify-email
	s.HandleFunc("/verify-email", verifyEmail(ctx)).Methods(h.MethodPost, h.MethodOptions)

	// POST /api/v1/auth/logout
	s.HandleFunc("/logout", logout(ctx)).Methods(h.MethodPost, h.MethodOptions)

	// POST /api/v1/auth/forgot-password
	s.HandleFunc("/forgot-password", forgotPassword(ctx)).Methods(h.MethodPost, h.MethodOptions)

	// POST /api/v1/auth/recover-password
	s.HandleFunc("/recover-password", recoverPassword(ctx)).Methods(h.MethodPost, h.MethodOptions)
}
