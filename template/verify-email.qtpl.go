// Code generated by qtc from "verify-email.qtpl". DO NOT EDIT.
// See https://github.com/valyala/quicktemplate for details.

//line template/verify-email.qtpl:1
package template

//line template/verify-email.qtpl:1
import (
	qtio422016 "io"

	qt422016 "github.com/valyala/quicktemplate"
)

//line template/verify-email.qtpl:1
var (
	_ = qtio422016.Copy
	_ = qt422016.AcquireByteBuffer
)

//line template/verify-email.qtpl:2
// VerifyEmailValues ...
type VerifyEmailValues struct {
	Name     string
	TokenURL string
	Company  string
}

//line template/verify-email.qtpl:10
func StreamVerifyEmail(qw422016 *qt422016.Writer, t VerifyEmailValues) {
//line template/verify-email.qtpl:10
	qw422016.N().S(`
Hi `)
//line template/verify-email.qtpl:11
	qw422016.E().S(t.Name)
//line template/verify-email.qtpl:11
	qw422016.N().S(`,

To complete your sign up, please verify your email:

`)
//line template/verify-email.qtpl:15
	qw422016.E().S(t.TokenURL)
//line template/verify-email.qtpl:15
	qw422016.N().S(`

Thank you, 
`)
//line template/verify-email.qtpl:18
	qw422016.E().S(t.Company)
//line template/verify-email.qtpl:18
	qw422016.N().S(` Team
`)
//line template/verify-email.qtpl:19
}

//line template/verify-email.qtpl:19
func WriteVerifyEmail(qq422016 qtio422016.Writer, t VerifyEmailValues) {
//line template/verify-email.qtpl:19
	qw422016 := qt422016.AcquireWriter(qq422016)
//line template/verify-email.qtpl:19
	StreamVerifyEmail(qw422016, t)
//line template/verify-email.qtpl:19
	qt422016.ReleaseWriter(qw422016)
//line template/verify-email.qtpl:19
}

//line template/verify-email.qtpl:19
func VerifyEmail(t VerifyEmailValues) string {
//line template/verify-email.qtpl:19
	qb422016 := qt422016.AcquireByteBuffer()
//line template/verify-email.qtpl:19
	WriteVerifyEmail(qb422016, t)
//line template/verify-email.qtpl:19
	qs422016 := string(qb422016.B)
//line template/verify-email.qtpl:19
	qt422016.ReleaseByteBuffer(qb422016)
//line template/verify-email.qtpl:19
	return qs422016
//line template/verify-email.qtpl:19
}
