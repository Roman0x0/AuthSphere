package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func ComparePassword(hashedPass, givenPass string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(givenPass))
	return err == nil
}

func CompareVerificationCode(normalCode, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(normalCode))
	return err == nil
}

func GetPrivateKey(in string) (*rsa.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return nil, err
	}

	return GetPriKeyFromPem(key)
}

func GetPriKeyFromPem(pub []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, nil
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}

	return pri, nil
}

func GetRSAKeys() (string, string) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privatekey)

	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)

	publickey := &privatekey.PublicKey

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		panic(err)
	}

	convertedPublicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)
	convertedPrivateKey := base64.StdEncoding.EncodeToString(privkey_pem)

	return convertedPrivateKey, convertedPublicKey
}
