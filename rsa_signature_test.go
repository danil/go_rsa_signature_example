package rsasignature_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	rsasignature "bitbucket.org/danil/go_rsa_signature_example"
)

var testCases = []struct {
	in        []byte
	out       bool
	signature string
	public    []byte
	private   []byte
}{
	{
		in:  []byte("пример"),
		out: true,
		// signature: "bb8e2d3f940f12c3c25aea2a588f7fc54b59be4770dee7e6b5b5702016b37218279b3e1ff2ff0eebb12641d3db9e1df021860344766d78c3b678f1890c3e0b60fa3a1b828c28b15fa89a4f78bf1e3820e5ac90a0167f3abe68ad210f7c88440e2e371ed60c1719c6ac057f8c1416704dba86279de7f28c7255ea5ca6774154f1",
		signature: "u44tP5QPEsPCWuoqWI9/xUtZvkdw3ufmtbVwIBazchgnmz4f8v8O67EmQdPbnh3wIYYDRHZteMO2ePGJDD4LYPo6G4KMKLFfqJpPeL8eOCDlrJCgFn86vmitIQ98iEQOLjce1gwXGcasBX+MFBZwTbqGJ53n8oxyVepcpndBVPE=",
		public: []byte(`-----BEGIN PUBLIC KEY-----
MIGJAoGBAObjuj/OdKXQNzws+2lrq8Ug8BVhUwoImCxHsVcx5oV2Nnt80GpLounI
KvaAdIQf7UChXevRek6owohOBNT69ly46D39wFHMF+FVQ7Wrm3N2oBirrP0poFMT
eY036kBb85P6jP3vvkQnrJy3R7E9QuBxT62SxcEPprpSR9PFFNeDAgMBAAE=
-----END PUBLIC KEY-----`),
		private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDm47o/znSl0Dc8LPtpa6vFIPAVYVMKCJgsR7FXMeaFdjZ7fNBq
S6LpyCr2gHSEH+1AoV3r0XpOqMKITgTU+vZcuOg9/cBRzBfhVUO1q5tzdqAYq6z9
KaBTE3mNN+pAW/OT+oz9775EJ6yct0exPULgcU+tksXBD6a6UkfTxRTXgwIDAQAB
AoGBAKeEYDQ9GXrYZ8rcJAinmveqXyZT94iXFblCxtMpnEQGsZ7Evv3wJKITncA9
EMxv0ZYLvfYDhQafAI0edfkEoEri7sFdmk1PYSLodODxVn3GC3USuxeXys7cj8tD
2fFWKNsntRVgwc/mMd7kY3h5suzvB/Len+H/aOBC7deP9R7BAkEA7nJCJ/a02vlt
aASj1ct5ycwtyuGF3xUtlQo2OLlxXX7zXi0DaTup1ZUGSv5P7LcM3bJ8uIvu0HTe
uRdbceNA4wJBAPfjDhGKQsz1SSzbyFwUY16MvG4Vh+PzZw1IbmGQhHrfHT7cPpF5
530E9XFBCSmtchW3kpQJeykOh8FzIY2s8OECQCEFicvnCpzYtiIVomrVRwR/Vkgm
e1etoyZkx6WLaPu9vQ5pxXMpZBfED58LIR5zK0D4mvUjy+rqhH21kmBvTGkCQQC4
933Z7LcnxKeTh3Qb8UKsnItGAV7i4w60RKXIu1N/c9iYvTMazkHDcd3LYmH57WhB
eDcxq1lxK1x1JvmUg8VBAkBb+x5ZyXMKhEfwv5WRyQOUHTToaBUhoczu/BjJ3bFM
8Ks+WR+ZSwiWN2rX7ls5KqiT0QVnpxcpLJNjlrGb4y7v
-----END RSA PRIVATE KEY-----`),
	},
}

func TestSignature(t *testing.T) {
	for _, tc := range testCases {
		if tc.signature == "" || tc.public == nil {
			privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
			if err != nil {
				t.Fatal(err)
			}
			tc.public, err = rsasignature.EncodePublicKeyPEM(&privateKey.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			// fmt.Println(string(tc.public))
			tc.private, err = rsasignature.EncodePrivateKeyPEM(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			// fmt.Println(string(tc.private))
			tc.signature, err = rsasignature.Sign(tc.private, tc.in)
			if err != nil {
				t.Fatal(err)
			}
			// fmt.Println(tc.signature)
		}
		ok, err := rsasignature.Verify(tc.public, tc.signature, tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if ok != tc.out {
			t.Errorf("verify expected %t, got %t: %q", tc.out, ok, tc.in)
		}
	}
}
