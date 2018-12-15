package rsasignature

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// Sign returns base64 encoded SignPKCS1v15 signature
// using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
func Sign(privateKeyPEM, bytesToSign []byte) (string, error) {
	privateKey, err := DecodePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}
	// crypto/rand.Reader is a good source of entropy for blinding the RSA
	// operation.
	rng := rand.Reader
	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(bytesToSign)
	signature, err := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	// return hex.EncodeToString(signature), nil
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify verifies an RSA PKCS#1 v1.5 signature
func Verify(publicKeyPEM []byte, signature string, signed []byte) (bool, error) {
	publicKey, err := DecodePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return false, err
	}
	// a, err := hex.DecodeString(signature)
	// if err == rsa.ErrVerification {
	// 	return false, err
	// }
	a, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	// fmt.Println(base64.StdEncoding.EncodeToString(a))
	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(signed)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], a)
	if err == rsa.ErrVerification {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// DecodePublicKeyPEM decodes RSA PKCS#1 v1.5 public key
func DecodePublicKeyPEM(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// DecodePrivateKeyPEM decodes RSA PKCS#1 v1.5 private key
func DecodePrivateKeyPEM(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// EncodePublicKeyPEM encodes RSA PKCS#1 v1.5 public key
func EncodePublicKeyPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyPEM := bytes.NewBuffer([]byte{})
	err := pem.Encode(publicKeyPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})
	if err != nil {
		return nil, err
	}
	return publicKeyPEM.Bytes(), nil
}

// EncodePrivateKeyPEM encodes RSA PKCS#1 v1.5 private key
func EncodePrivateKeyPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyPEM := bytes.NewBuffer([]byte{})
	err := pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, err
	}
	return privateKeyPEM.Bytes(), nil
}
