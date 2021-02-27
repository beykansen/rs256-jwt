package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"strings"
	"time"
)

func GenerateJwt(ttl time.Duration, privateKey []byte, kid string, content interface{}) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}
	now := time.Now().UTC()
	claims := make(jwt.MapClaims)
	claims["dat"] = content
	claims["iss"] = "beykan"
	claims["exp"] = now.Add(ttl).Unix()
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jwtToken.Header["kid"] = kid
	token, err := jwtToken.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}
	return token, nil
}

func ValidateJwt(token string, publicKey []byte) (interface{}, error) {
	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		//openid için bunu jwk urlinden bulup dönüyoruz kid kısmını okumak gerekiyor
		key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
		if err != nil {
			return "", fmt.Errorf("validate: parse key: %w", err)
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}

	return claims["dat"], nil
}

func ConvertPublicKeyToResponseFormat(publicKey []byte) string {
	stringPublicKey := string(publicKey)
	stringPublicKey = strings.Replace(stringPublicKey, "-----BEGIN CERTIFICATE-----", "", -1)
	stringPublicKey = strings.Replace(stringPublicKey, "-----END CERTIFICATE-----", "", -1)
	stringPublicKey = strings.Replace(stringPublicKey, "\n", "", -1)
	stringPublicKey = strings.Replace(stringPublicKey, "\r", "", -1)
	stringPublicKey = strings.Replace(stringPublicKey, "\r\n", "", -1)
	return stringPublicKey
}
