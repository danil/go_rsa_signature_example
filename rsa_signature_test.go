package rsasignature_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"runtime"
	"testing"

	rsasignature "github.com/danil/go_rsa_signature_example"
)

var testCases = []struct {
	name      string
	index     int
	in        []byte
	out       bool
	signature string
	public    []byte
	private   []byte
	skip      string
}{
	{
		name:  "generate keys then sign and verify",
		index: getLine(),
		in:    []byte("пример"),
		out:   true,
	},
	{
		name:  "get public key by private key then sign and verify",
		index: getLine(),
		in:    []byte("пример"),
		out:   true,
		private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAy0fIwV+TZG7/1amjEx35A6yMKuZ4eY/79jEoAae1uGSn//Tb
HEHkEeoMH8JA9yOhcykYS2ox3iAJ4mNhBGbrFGl5N1VGBhftjbbZNTV0OcGK2t0p
KnpKdhTD3AfB3HOrquLTVYcZCBx6tQEk/1NMFQDK0JOzowqoZnlWqBcMhWyDmoLL
Fr5IIwyiVZAlA3a62FL/1D5ke47vafzYZXZA7fOHUQX1vYojSLgSNPQ4Z/rzC998
Nlj5B6jMed1qcFT7cQYyGk4R7Yc/6zcHd7uUhDCOK4xq4hQNdmwGhStQgHgJgWha
rj6XjcebpNEJc9TSKB+U2igWThz2CNJd+i64tQIDAQABAoIBACEx8biSMPF/pstv
Ti/6/wT4klMXG6lON+j2EgBjMKuR1FVZ2MX+hI3gWGZ/RDiXWvABT/RQvR/2v2Z2
sAsV+2Fz79V3WV35XlN7/nBP8FDWKCShZO2I1sv9jBZMNf4X7XqUW8plq1LFw8v3
CeGf6parcHMrC3Secu149wuv592JllBYtVBKugH/wCgQq0tmorL094Hka24jgeIC
TqnI+TozgvfpJKJWomBBdwF+dJDMhYFqDgzQStOeTF2+tj1G0mIyIdPt4tPezvDh
S4zR9nY0nKWiNadIhnWyJEFzYC4dIKjCK/wXEvrN6/QCmBcBh39ISumuE82XfoX6
+oCsiykCgYEA3KkK3u681UY0SpBpcmeLkMpQWrlzgsHEbHfcQKNRu/iKd5WdRY+1
X2aOkQDu2BizpijP7GkZc7Qhhc9heli8ozBS9AaeF/pJqIvqMQ7+MMD95KZ8O6yw
1/PIYctJPoX9pL7UC6lc07cGhFw1S/+cju5ZLhftfQOh2UpaeqKeOkcCgYEA69Ys
oMgtmWfUm4SkGwuhV6hOp22n4MFsW97wNX1a8FWynR4adEs5Kt1t+8xQPyxgRC5r
9N6/++E1Rqo4GVTzTLLWdAppuhZproj252PfIpkq1/fQhj6RnxddOM4tPPPL/iSJ
9QXcehH1487KblVrP+e7WGgq3w1CtFGLihP8tyMCgYEA2/k02hsbam2rMW4XgLJS
wsu9IURhL8fk/dDbZCCsGXxi5WXkO/VQdUNy+oD4mbq+VPW4mdAITH0VMiUT4vjV
TMWe3KBAOF0N0xVwKOnuY0HxmWCS1paIUTA44azbXpYKzpJiJyH2ZSS/PXICu7md
JCveAYJfAVJ+pXRnEHxOyn8CgYB6uzj6a3KflRNl479re7/5WFOmekCVjNORdBHa
JGSBEngjoBjwUH1tu1KTaZ6RYcyvbuErzAhpUqhhIBCVzknXrnJAbXLcLvHMrOah
QK5M2R0cy5CvbDxoaMZQ26tbPxz4I5fP9b7poBMw/NsIVFe+KCCtP3igH8yI/q75
qrEntQKBgDD6qizPwHrCwxl+vVbT0ZIvNGu6kSHDnJQNZuQjP4BC0d/flx0H9qMc
fgd8jkt30nN5CqBZAguggF6Awno26DExnFGAgLKoNHg1jHTIOZeCHgJzW4slXyXY
Z8fztgJFeN+KP6sJJxCDVdORSRPzFCKVW1pVKSETWWwTf+/drKHb
-----END RSA PRIVATE KEY-----`),
	},
	{
		name:      "verify",
		index:     getLine(),
		in:        []byte("пример"),
		out:       true,
		signature: "LcZpeFAi25p8tYL5ANx+LG4ZrOxyukD9eqMf5h8AJgGbr/hhBlpcbl+ZNLd2nsEdknPtsRYmd2Ac+6SDAh9BUPfLslZMP0tS38AdIyfxN86fP1ZhxUn/m91x8krS/eiqxpq9GY1wTboK08ojtHmUCZmyCbFOwY2Fmf86rY4FYJDE8dUeDOluoQGDUK4upjnrcaLnxcWahzEnAkcbI36zK9fvhaGM0eN2KQEPqSUBJE4O2oR0J0MIzFQrUsCiSlZFD6Mt62VVjzuSeeY6C/3YODsz+2YiaJa5uXn5wQXBk4cbjk+G5+Hw2R5p1vJxAfwO1/q2h16WLLiyg+Dn/pvPMA==",
		public: []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0fIwV+TZG7/1amjEx35
A6yMKuZ4eY/79jEoAae1uGSn//TbHEHkEeoMH8JA9yOhcykYS2ox3iAJ4mNhBGbr
FGl5N1VGBhftjbbZNTV0OcGK2t0pKnpKdhTD3AfB3HOrquLTVYcZCBx6tQEk/1NM
FQDK0JOzowqoZnlWqBcMhWyDmoLLFr5IIwyiVZAlA3a62FL/1D5ke47vafzYZXZA
7fOHUQX1vYojSLgSNPQ4Z/rzC998Nlj5B6jMed1qcFT7cQYyGk4R7Yc/6zcHd7uU
hDCOK4xq4hQNdmwGhStQgHgJgWharj6XjcebpNEJc9TSKB+U2igWThz2CNJd+i64
tQIDAQAB
-----END RSA PUBLIC KEY-----`),
	},
	{
		name:      "fail verification of the wrong word",
		index:     getLine(),
		in:        []byte("пример2"),
		out:       false,
		signature: "LcZpeFAi25p8tYL5ANx+LG4ZrOxyukD9eqMf5h8AJgGbr/hhBlpcbl+ZNLd2nsEdknPtsRYmd2Ac+6SDAh9BUPfLslZMP0tS38AdIyfxN86fP1ZhxUn/m91x8krS/eiqxpq9GY1wTboK08ojtHmUCZmyCbFOwY2Fmf86rY4FYJDE8dUeDOluoQGDUK4upjnrcaLnxcWahzEnAkcbI36zK9fvhaGM0eN2KQEPqSUBJE4O2oR0J0MIzFQrUsCiSlZFD6Mt62VVjzuSeeY6C/3YODsz+2YiaJa5uXn5wQXBk4cbjk+G5+Hw2R5p1vJxAfwO1/q2h16WLLiyg+Dn/pvPMA==",
		public: []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0fIwV+TZG7/1amjEx35
A6yMKuZ4eY/79jEoAae1uGSn//TbHEHkEeoMH8JA9yOhcykYS2ox3iAJ4mNhBGbr
FGl5N1VGBhftjbbZNTV0OcGK2t0pKnpKdhTD3AfB3HOrquLTVYcZCBx6tQEk/1NM
FQDK0JOzowqoZnlWqBcMhWyDmoLLFr5IIwyiVZAlA3a62FL/1D5ke47vafzYZXZA
7fOHUQX1vYojSLgSNPQ4Z/rzC998Nlj5B6jMed1qcFT7cQYyGk4R7Yc/6zcHd7uU
hDCOK4xq4hQNdmwGhStQgHgJgWharj6XjcebpNEJc9TSKB+U2igWThz2CNJd+i64
tQIDAQAB
-----END RSA PUBLIC KEY-----`),
	},
}

func TestSignature(t *testing.T) {
	_, fileName, _, _ := runtime.Caller(0)
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			linkToExample := fmt.Sprintf("[Example][%s:%d]", fileName, tc.index)
			if tc.skip != "" {
				t.Skip(tc.skip, linkToExample)
			}
			var err error
			if tc.public == nil {
				var privateKey *rsa.PrivateKey
				if tc.private == nil {
					privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
					if err != nil {
						t.Fatal(err, linkToExample)
					}
					tc.private, err = rsasignature.EncodePrivateKeyPEM(privateKey)
					if err != nil {
						t.Fatal(err, linkToExample)
					}
					// fmt.Println(string(tc.private))
				} else {
					privateKey, err = rsasignature.DecodePrivateKeyPEM(tc.private)
					if err != nil {
						t.Fatal(err, linkToExample)
					}
				}
				// tc.public, err = rsasignature.EncodePublicKeyPEM(&privateKey.PublicKey)
				// if err != nil {
				// 	t.Fatal(err, linkToExample)
				// }
				tc.public, err = rsasignature.EncodePKIXPublicKeyPEM(&privateKey.PublicKey)
				if err != nil {
					t.Fatal(err, linkToExample)
				}
				// fmt.Println(string(tc.public))
			}
			if tc.signature == "" {
				tc.signature, err = rsasignature.Sign(tc.private, tc.in)
				if err != nil {
					t.Fatal(err, linkToExample)
				}
				// fmt.Println(tc.signature)
			}
			ok, err := rsasignature.Verify(tc.public, tc.signature, tc.in)
			if err != nil {
				t.Fatal(err, linkToExample)
			}
			if ok != tc.out {
				t.Errorf("[error] expected: %t, received: %t: %q - %s",
					tc.out, ok, tc.in, linkToExample)
			}
		})
	}
}

func getLine() int {
	_, _, line, _ := runtime.Caller(1)
	return line
}
