package template

import (
	"fmt"
	"log"

	"github.com/microapis/email-api"
	emailClient "github.com/microapis/email-api/client"
	"github.com/microapis/users-api"
)

// VerifyEmailTemplate ...
func VerifyEmailTemplate(ec *emailClient.Client) func(u *users.User, token string) error {
	return func(u *users.User, token string) error {
		// define template intepolation values
		vet := VerifyEmailValues{
			Name:     u.Name,
			TokenURL: fmt.Sprintf("https://www.microapis.dev/email-verification?token=%s", token),
			Company:  "MicroAPIs",
		}

		// generate template with interpolation
		str := VerifyEmail(vet)

		// send email with token and url
		id, err := ec.Send(&email.Message{
			From:     "no-reply@microapis.dev",
			FromName: u.Name,
			To:       []string{u.Email},
			Subject:  fmt.Sprintf("[%s]: Please verify your email address", vet.Company),
			Text:     str,
			Provider: "sendgrid",
		}, 0)
		if err != nil {
			return err
		}

		log.Printf("Send email for Verify email, email=%s id=%s", u.Email, id)

		return nil
	}
}
