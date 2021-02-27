package main

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

type handler struct {
	privateKey []byte
	publicKey  []byte
	kid        string
}

func newHandler(privateKey []byte, publicKey []byte, kid string) *handler {
	return &handler{privateKey: privateKey, publicKey: publicKey, kid: kid}
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	prvKey, err := ioutil.ReadFile("key.pem")
	if err != nil {
		log.Fatalln(err)
	}
	pubKey, err := ioutil.ReadFile("public.cer")
	if err != nil {
		log.Fatalln(err)
	}
	h := newHandler(prvKey, pubKey, "ABC")
	e.GET("/", h.generateToken)
	e.GET("/jwks", h.getJwtks)
	e.GET("/validate", h.validateToken)

	e.Logger.Fatal(e.Start(":8080"))
}

func (h *handler) getJwtks(c echo.Context) error {

	response := &getJwksResponse{}
	response.Keys = make([]key, 0)
	//todo fill remains
	response.Keys = append(response.Keys, key{
		Kty: "RSA",
		Use: "",
		Kid: h.kid,
		X5T: "",
		E:   "",
		N:   "",
		X5C: []string{ConvertPublicKeyToResponseFormat(h.publicKey)},
		Alg: "RS256",
	})

	return c.JSON(http.StatusOK, response)
}
func (h *handler) generateToken(c echo.Context) error {
	tok, err := GenerateJwt(time.Hour*12, h.privateKey, h.kid, "Can be anything")
	if err != nil {
		log.Fatalln(err)
	}
	return c.String(http.StatusOK, tok)
}

func (h *handler) validateToken(c echo.Context) error {
	token := c.Request().Header.Get("Authorization")
	if len(token) == 0 {
		return c.String(http.StatusUnauthorized, "token is missing")
	}
	token = strings.Replace(token, "Bearer ", "", -1)

	claims, err := ValidateJwt(token, h.publicKey)
	if err != nil {
		return c.String(http.StatusUnauthorized, "token is not valid")
	}
	return c.String(http.StatusOK, fmt.Sprintf("%v", claims))
}

type getJwksResponse struct {
	Keys []key `json:"keys"`
}
type key struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5T string   `json:"x5t"`
	E   string   `json:"e"`
	N   string   `json:"n"`
	X5C []string `json:"x5c"`
	Alg string   `json:"alg"`
}
