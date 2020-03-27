package template

import (
	"fmt"
	"log"

	"github.com/microapis/users-api"
	"github.com/microapis/email-api"
	emailClient "github.com/microapis/email-api/client"
)

// SignupTemplate ...
func SignupTemplate(ec *emailClient.Client) func(u *users.User) error {
	return func(u *users.User) error {
		// define template intepolation values
		st := SignupValues{
			Name:      u.Name,
			Company:    "MicroAPIs",
		}
	
		// generate template with interpolation
		str := Signup(st)
	
		// send email with token and url
		id, err := ec.Send(&email.Message{
			From:     "no-reply@microapis.dev",
			FromName: u.Name,
			To:       []string{u.Email},
			Subject:  fmt.Sprintf("Welcome to %s!", st.Company),
			Text:     str,
			Provider: "sendgrid",
		}, 0)
		if err != nil {
			return err
		}
	
		log.Printf("Send email for Signup, email=%s id=%s", u.Email, id)
	
		return nil
	}
}