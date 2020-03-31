package http

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/microapis/auth-api"
	"github.com/microapis/users-api"
)

func getByToken(ctx handlerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get token param
		vars := mux.Vars(r)
		token := vars["token"]
		fmt.Println(fmt.Sprintf("[Gateway][Auth][GetByToken][Request] token = %v", token))

		// validate token param
		if token == "" {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][GetByToken][Error] %v", "invalid token"))
			http.Error(w, "invalid token", http.StatusInternalServerError)
			return
		}

		// get auth by token
		auth, err := ctx.AuthClient.GetByToken(token)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][GetByToken][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res := Response{
			Data: auth,
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][GetByToken][Response] %v", res))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][GetByToken][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func login(ctx handlerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// define payload struct
		payload := new(struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		})

		// read body and define string
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Login][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// decode body string to payload
		err = json.Unmarshal(body, payload)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Login][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][Login][Request] email = %v password = %v", payload.Email, payload.Password))

		// get and validate email and password params
		if payload.Email == "" || payload.Password == "" {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Login][Error] %v", "invalid email or password"))
			http.Error(w, "invalid email or password", http.StatusInternalServerError)
			return
		}

		// login with email and password on users-api
		resLogin, err := ctx.AuthClient.Login(payload.Email, payload.Password)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Login][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO(ca): fix bug #1 - fix error calling MarshalJSON for
		//           type time.Time: Time.MarshalJSON: year outside
		//           of range [0,9999] when call signup or login auth
		//					 method (created_at and updated_at).
		user := users.User{
			ID:    resLogin.Data.ID,
			Name:  resLogin.Data.Name,
			Email: resLogin.Data.Email,
		}

		res := Response{
			Data: user,
			Meta: resLogin.Meta,
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][Login][Response] %v", res))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Login][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func signup(ctx handlerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// define payload struct
		payload := new(struct {
			User *struct {
				Email    string `json:"email"`
				Name     string `json:"name"`
				Password string `json:"password"`
			} `json:"user"`
		})

		// read body and define string
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Signup][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// decode body string to payload
		err = json.Unmarshal(body, payload)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Signup][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][Signup][Request] user = %v", payload))

		// get and validate user param
		if payload.User == nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Signup][Error] %v", "invalid user"))
			http.Error(w, "invalid user", http.StatusInternalServerError)
			return
		}

		// validate user params
		if payload.User.Email == "" || payload.User.Name == "" || payload.User.Password == "" {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Signup][Error] %v", "invalid user params"))
			http.Error(w, "invalid user params", http.StatusInternalServerError)
			return
		}

		// create user definition
		user := &users.User{
			Email:    payload.User.Email,
			Name:     payload.User.Name,
			Password: payload.User.Password,
		}

		// signup created user
		resSignup, err := ctx.AuthClient.Signup(user)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Signup][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO(ca): fix bug #2 - fix error calling MarshalJSON for
		//           type time.Time: Time.MarshalJSON: year outside
		//           of range [0,9999] when call signup or login auth
		//					 method (created_at and updated_at).
		u := users.User{
			ID:    resSignup.Data.ID,
			Name:  resSignup.Data.Name,
			Email: resSignup.Data.Email,
		}

		res := Response{
			Data: u,
			Meta: resSignup.Meta,
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][Signup][Response] %v", res))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Signup][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func verifyToken(ctx handlerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// define payload struct
		payload := new(struct {
			Token string `json:"token"`
			Kind  string `json:"kind"`
		})

		// read body and define string
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyToken][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// decode body string to payload
		err = json.Unmarshal(body, payload)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyToken][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyToken][Request] token = %v kind = %v", payload.Token, payload.Kind))

		// get and validate token and kind params
		if payload.Token == "" || payload.Kind == "" {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyToken][Error] %v", "invalid token or kind"))
			http.Error(w, "invalid token or kind", http.StatusInternalServerError)
			return
		}

		t, err := ctx.AuthClient.VerifyToken(payload.Token, payload.Kind)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyToken][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res := Response{
			Data: t,
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyToken][Response] %v", res))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyToken][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func verifyEmail(ctx handlerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// define payload struct
		payload := new(struct {
			Token string `json:"token"`
		})

		// read body and define string
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyEmail][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// decode body string to payload
		err = json.Unmarshal(body, payload)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyEmail][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyEmail][Request] token = %v", payload.Token))

		// get and validate token and kind params
		if payload.Token == "" {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyEmail][Error] %v", "invalid token"))
			http.Error(w, "invalid token", http.StatusInternalServerError)
			return
		}

		err = ctx.AuthClient.VerifyEmail(payload.Token)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyEmail][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res := Response{}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyEmail][Response] %v", res))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][VerifyEmail][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func logout(ctx handlerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// define payload struct
		payload := new(struct {
			Token string `json:"token"`
		})

		// read body and define string
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// decode body string to payload
		err = json.Unmarshal(body, payload)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Request] token = %v", payload.Token))

		// get and validate token param
		if payload.Token == "" {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", "invalid token"))
			http.Error(w, "invalid token", http.StatusInternalServerError)
			return
		}

		err = ctx.AuthClient.Logout(payload.Token)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res := Response{}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Response] %v", res))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func forgotPassword(ctx handlerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// define payload struct
		payload := new(struct {
			Email string `json:"email"`
		})

		// read body and define string
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// decode body string to payload
		err = json.Unmarshal(body, payload)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][ForgotPassword][Request] email = %v", payload.Email))

		// get and validate email param
		if payload.Email == "" {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][ForgotPassword][Error] %v", "invalid email"))
			http.Error(w, "invalid email", http.StatusInternalServerError)
			return
		}

		token, err := ctx.AuthClient.ForgotPassword(payload.Email)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][ForgotPassword][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res := Response{
			Data: auth.MetaToken{
				Token: token,
			},
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][ForgotPassword][Response] %v", res))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][ForgotPassword][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func recoverPassword(ctx handlerContext) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// define payload struct
		payload := new(struct {
			NewPassword string `json:"new_password"`
			Token       string `json:"token"`
		})

		// read body and define string
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		// decode body string to payload
		err = json.Unmarshal(body, payload)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][Logout][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][RecoverPassword][Request] newPassword = %v token = %v", payload.NewPassword, payload.Token))

		// get and validate token and newPassword params
		if payload.NewPassword == "" || payload.Token == "" {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][RecoverPassword][Error] %v", "invalid newPassword or token"))
			http.Error(w, "invalid new_password or token", http.StatusInternalServerError)
			return
		}

		err = ctx.AuthClient.RecoverPassword(payload.NewPassword, payload.Token)
		if err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][RecoverPassword][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res := Response{}

		fmt.Println(fmt.Sprintf("[Gateway][Auth][RecoverPassword][Response] %v", res))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			fmt.Println(fmt.Sprintf("[Gateway][Auth][RecoverPassword][Error] %v", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
