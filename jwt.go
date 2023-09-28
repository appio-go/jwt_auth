package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"os"
	"time"
)

type Claims struct {
	Email    string `json:"email"`
	BundleID string `json:"bundle_id"`
	jwt.RegisteredClaims
}

func LoadPrivateKey(fileName string) (*rsa.PrivateKey, error) {
	priv, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile: %w", err)
	}

	block, _ := pem.Decode(priv)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey: %w", err)
	}

	val, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key.(*rsa.PrivateKey): %w", err)
	}

	return val, nil
}

func LoadPublicKey(fileName string) (*rsa.PublicKey, error) {
	pub, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile: %w", err)
	}

	block, _ := pem.Decode(pub)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	val, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key.(*rsa.PublicKey): %w", err)
	}

	return val, nil
}

func (j Claims) Create(email, bundle, appName string, key *rsa.PrivateKey) (res string, err error) {

	claims := Claims{
		email,
		bundle,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(744 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    appName,
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	res, err = t.SignedString(key)
	if err != nil {
		log.Println("t.SignedString err:", err.Error())
		return res, err
	}

	return
}

func ValidateJWT(tokenRaw string, key *rsa.PublicKey) (jwtCl Claims, valid bool) {

	token, err := jwt.ParseWithClaims(tokenRaw, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithLeeway(5*time.Second))

	if token == nil || token.Claims == nil {
		return jwtCl, false
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return *claims, true
	} else {
		if err != nil {
			log.Println("invalid jwt:", err.Error())
		}
		return jwtCl, false
	}
}
