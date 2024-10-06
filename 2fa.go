package main

import (
	"encoding/base32"
	"encoding/base64"
	"math/rand"
	"net/url"

	"github.com/dgryski/dgoogauth"
	"rsc.io/qr"
)

func GenerateSecretKey() string {
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	if err != nil {
		panic(err)
	}
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	return secretBase32
}

func GenerateQRCode(issuer, secret string) string {
	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		panic(err)
	}

	URL.Path += "/" + url.PathEscape(issuer)

	params := url.Values{}
	params.Add("secret", secret)
	params.Add("issuer", issuer)

	URL.RawQuery = params.Encode()

	code, err := qr.Encode(URL.String(), qr.Q)
	if err != nil {
		panic(err)
	}

	encoded := base64.StdEncoding.EncodeToString(code.PNG())
	return encoded
}

func Verify2FACode(secret, token string) bool {
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}

	val, err := otpc.Authenticate(token)
	if err != nil {
		return false
	}

	if !val {
		return false
	}

	return true
}
