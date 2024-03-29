// Code generated by qtc from "password-changed.qtpl". DO NOT EDIT.
// See https://github.com/valyala/quicktemplate for details.

//line template/password-changed.qtpl:1
package template

//line template/password-changed.qtpl:1
import (
	qtio422016 "io"

	qt422016 "github.com/valyala/quicktemplate"
)

//line template/password-changed.qtpl:1
var (
	_ = qtio422016.Copy
	_ = qt422016.AcquireByteBuffer
)

//line template/password-changed.qtpl:2
// PasswordChangedValues ...
type PasswordChangedValues struct {
	Name    string
	Company string
}

//line template/password-changed.qtpl:9
func StreamPasswordChanged(qw422016 *qt422016.Writer, t PasswordChangedValues) {
//line template/password-changed.qtpl:9
	qw422016.N().S(`
Dear `)
//line template/password-changed.qtpl:10
	qw422016.E().S(t.Name)
//line template/password-changed.qtpl:10
	qw422016.N().S(`,
Your `)
//line template/password-changed.qtpl:11
	qw422016.E().S(t.Company)
//line template/password-changed.qtpl:11
	qw422016.N().S(` account password has been successfully changed.

We are sending this notice to ensure the privacy and security of your `)
//line template/password-changed.qtpl:13
	qw422016.E().S(t.Company)
//line template/password-changed.qtpl:13
	qw422016.N().S(` account. If you authorized this change, no further action is necessary.

If you did not authorize this change, then please change your `)
//line template/password-changed.qtpl:15
	qw422016.E().S(t.Company)
//line template/password-changed.qtpl:15
	qw422016.N().S(` password, and consider changing your email password as well to ensure your account security.

If you are unable to access your account, then you may use this account specific recovery link for assistance recovering or self-locking your account.

The `)
//line template/password-changed.qtpl:19
	qw422016.E().S(t.Company)
//line template/password-changed.qtpl:19
	qw422016.N().S(` Team
`)
//line template/password-changed.qtpl:20
}

//line template/password-changed.qtpl:20
func WritePasswordChanged(qq422016 qtio422016.Writer, t PasswordChangedValues) {
//line template/password-changed.qtpl:20
	qw422016 := qt422016.AcquireWriter(qq422016)
//line template/password-changed.qtpl:20
	StreamPasswordChanged(qw422016, t)
//line template/password-changed.qtpl:20
	qt422016.ReleaseWriter(qw422016)
//line template/password-changed.qtpl:20
}

//line template/password-changed.qtpl:20
func PasswordChanged(t PasswordChangedValues) string {
//line template/password-changed.qtpl:20
	qb422016 := qt422016.AcquireByteBuffer()
//line template/password-changed.qtpl:20
	WritePasswordChanged(qb422016, t)
//line template/password-changed.qtpl:20
	qs422016 := string(qb422016.B)
//line template/password-changed.qtpl:20
	qt422016.ReleaseByteBuffer(qb422016)
//line template/password-changed.qtpl:20
	return qs422016
//line template/password-changed.qtpl:20
}
