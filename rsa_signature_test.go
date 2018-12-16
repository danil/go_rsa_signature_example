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
		name:      "verify",
		index:     getLine(),
		in:        []byte("пример"),
		out:       true,
		signature: "dchEsKOm7cdxW/LAPovvEe2iv6LUOlF4q1XpNSbxc61/0dCpm83liVBGnsTTufa2VWqslYEqyXlQFYOPXcLznTBYqTON8laskgd9LK/QXzUKnE3pErmzrgZ8dmGct5HLElTbuuja7iRAaBGB6ka6G8a6dZDfQfGEYtx+QEGg+og3TSSZdP9HAVeFlKmQOp9j5AY/r3q4ys0aWAMceIuR9C9vQ3q8h3WA53AxT5lmwhhP7QzIDwFY3oWj0ZpukleLQYAT1QN5rer0Q6ThsnO5DsxtnI5y1tLOIemsvRtoqUXRBFJSBO6g3im03XkvLzg9BerDJvwydGCmpTa9PFchYA==",
		public: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnQtaNCjDySvY1Jci9LvA
zaDUezB23i/NlHS43OWaYfI+bdJo0q2PPcopF2Ii9cuR5AacxyYQjncckGdPgnsO
G7U3/cazeFUBF3O20SX9sV8Lgy5BOMrsnlmn4u9RDrViF67Vaxm+DNfBs1l51lCa
JTIEzMzlmdkeNyS/Y/KqGDKxCLlTMiR3NRj1W9QWAuFj3U/4MgUv4dw7k4UJIKvv
BuLTxxxLXuHVz8DvIbs0fRe5Ab7hS0J9Hxhd4K45nAjpKO+8YNkpAk9kMMDTDGXs
BRKgvIQ1GbIle0LCVWCfKJYY07C18SGfGw9ACNHeQFvZkZwfh9J5XLvhTMNFhfc/
PQIDAQAB
-----END PUBLIC KEY-----`),
	},
	{
		name:      "fail verification of the wrong word",
		index:     getLine(),
		in:        []byte("пример2"),
		out:       false,
		signature: "dchEsKOm7cdxW/LAPovvEe2iv6LUOlF4q1XpNSbxc61/0dCpm83liVBGnsTTufa2VWqslYEqyXlQFYOPXcLznTBYqTON8laskgd9LK/QXzUKnE3pErmzrgZ8dmGct5HLElTbuuja7iRAaBGB6ka6G8a6dZDfQfGEYtx+QEGg+og3TSSZdP9HAVeFlKmQOp9j5AY/r3q4ys0aWAMceIuR9C9vQ3q8h3WA53AxT5lmwhhP7QzIDwFY3oWj0ZpukleLQYAT1QN5rer0Q6ThsnO5DsxtnI5y1tLOIemsvRtoqUXRBFJSBO6g3im03XkvLzg9BerDJvwydGCmpTa9PFchYA==",
		public: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnQtaNCjDySvY1Jci9LvA
zaDUezB23i/NlHS43OWaYfI+bdJo0q2PPcopF2Ii9cuR5AacxyYQjncckGdPgnsO
G7U3/cazeFUBF3O20SX9sV8Lgy5BOMrsnlmn4u9RDrViF67Vaxm+DNfBs1l51lCa
JTIEzMzlmdkeNyS/Y/KqGDKxCLlTMiR3NRj1W9QWAuFj3U/4MgUv4dw7k4UJIKvv
BuLTxxxLXuHVz8DvIbs0fRe5Ab7hS0J9Hxhd4K45nAjpKO+8YNkpAk9kMMDTDGXs
BRKgvIQ1GbIle0LCVWCfKJYY07C18SGfGw9ACNHeQFvZkZwfh9J5XLvhTMNFhfc/
PQIDAQAB
-----END PUBLIC KEY-----`),
	},
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
MIIEogIBAAKCAQEAnQtaNCjDySvY1Jci9LvAzaDUezB23i/NlHS43OWaYfI+bdJo
0q2PPcopF2Ii9cuR5AacxyYQjncckGdPgnsOG7U3/cazeFUBF3O20SX9sV8Lgy5B
OMrsnlmn4u9RDrViF67Vaxm+DNfBs1l51lCaJTIEzMzlmdkeNyS/Y/KqGDKxCLlT
MiR3NRj1W9QWAuFj3U/4MgUv4dw7k4UJIKvvBuLTxxxLXuHVz8DvIbs0fRe5Ab7h
S0J9Hxhd4K45nAjpKO+8YNkpAk9kMMDTDGXsBRKgvIQ1GbIle0LCVWCfKJYY07C1
8SGfGw9ACNHeQFvZkZwfh9J5XLvhTMNFhfc/PQIDAQABAoIBACmxVN5aIDhtWqB+
C3q7yeENnLujzzsHp+WM43NJxaXRQT+4x7l++HNoE2aw2CU3SWEnXEIG2ghomP3B
X7t9Xe5/OwE12nnM34BRaSy3kFWhrRXDlu8z+IPFu6uk63kjMIqnEOPhLrKMKVGr
JIyAU5wiXmHc1+vzV3E+YU1wpDXN/PWNZbfu0xdEmfG9pEA3IOXkv5H/nRrPnirK
SzsrS/zyivz/W+3XLUwLHMf/wSBti9nl5Ezo9dnb+I2lknXH2NetR+c/0OvSj7ld
c08eq8BWXyNFQvkZaTsFhlJdjFcxcKDytlNFlseZlIBO3JFNsJhOKTV4xg1ldmzT
HGUilyECgYEAy8r1ndxAcr8SIJp3DlIn436ZwrUhzQn8rFMMzUihYTW+XI0Tj8C5
gU8f0E0O4xvEKEk4YT/mdwAmnPW6FX0NbPd5jg+qSJ/R6oOAYYUMVe3J/4Emg0lL
xphEE59HddoreB2r/fI6Au22ssHTrb1eqIG42DEAEN3MUILFFhhvoaUCgYEAxUaO
0vavua+L1oBOcvfurKC4v18mSW1Db2Bcmf0ciBM6RaYkyub1VMOZYjtKtO3QzWwQ
K98VLpXrlSLVavJSiSIkoVbhoNAkhjLzXUKFQgDUQPtEpg18EXU8Xv7I6xY21sM9
p+oDSQ7PZCeeUXerqmtDHWG1zCXWimJqsasEg7kCgYBgBVYrNh7Lsgl5gS49eio/
P2R1YGD3ug/qpgrvIpyfL/JsqzAfWIBPVBe6TsSH74pCLRW6hKAzS8flxsYR3+UW
hZgpfmoOY/dFVwaDbGv+hNbbY1/hFgT1IsNYt4C1H8HBi8GBGsOIo7akjT0OrJ5Q
KScN/jB4wfjFqofwPD1E3QKBgDCg+vX//0M7hbIDgNMQUNJW8BOkhdCV0Yiz7T+8
R/s3GicvFGS71//kE3xGd1zwPodUuwvFevg31pG1u3wYbcYGF5d5zjaQ+F/oUVtM
2YJyp9+40KxKKKo5Bv+3uJlSqYP5LsqkgdjRgMgEiB8266cft7SXcHP5Y9BLAFf5
eyxpAoGAM50bgJ32u2IhO1/ZGFPD78c2dTAvHncyaZm2/jFf7Y9galEx07FPfRWF
6AOd0GOhoDsMHjAnx/2BQI9lAdoI3iFVbp3Lg/WB6WR4/96Wy4/w551XI2JnJnON
oVL8VxqMtRXhbgr9NxX0qF8HmMqQhxIDwmOv4dIgqSuq2QWrcCM=
-----END RSA PRIVATE KEY-----`),
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
