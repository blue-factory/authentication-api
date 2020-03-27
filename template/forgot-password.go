package template

import (
	"fmt"
	"log"

	"github.com/microapis/email-api"
	emailClient "github.com/microapis/email-api/client"
	"github.com/microapis/users-api"
)

// ForgotPasswordTemplate ...
func ForgotPasswordTemplate(ec *emailClient.Client) func(u *users.User, token string) error {
	return func(u *users.User, token string) error {
		// define template intepolation values
		fpt := ForgotPasswordValues{
			Email:      u.Email,
			TokenURL:   fmt.Sprintf("https://www.microapis.dev/password-reset?token=%s", token),
			ExpireTime: "5 minutes",
			Company:    "MicroAPIs",
		}

		// generate template with interpolation
		str := ForgotPassword(fpt)

		// send email with token and url
		id, err := ec.Send(&email.Message{
			From:     "no-reply@microapis.dev",
			FromName: u.Name,
			To:       []string{u.Email},
			Subject:  fmt.Sprintf("[%s]: Instructions for changing your %s password", fpt.Company),
			Text:     str,
			Provider: "sendgrid",
		}, 0)
		if err != nil {
			return err
		}

		log.Printf("Send email for Forgot password, email=%s id=%s", u.Email, id)
		return nil
	}
}
