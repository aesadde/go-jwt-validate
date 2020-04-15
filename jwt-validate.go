package jwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/dgrijalva/jwt-go"
)

var (
	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("middleware header is empty")

	// ErrInvalidAuthHeader indicates middleware header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("middleware header is invalid")

	ErrInvalidKeyPath = errors.New("middleware pub key path is invalid")
)

type JWTMiddleware struct {
	PubKeyPath   string
	pubKey       *rsa.PublicKey
	HeaderName   string
	HeaderPrefix string
}

func NewJWTValidationMiddleware(jwtm *JWTMiddleware) (*JWTMiddleware, error) {
	if jwtm.PubKeyPath == "" {
		return nil, ErrInvalidKeyPath
	}

	//Read and decode Public key
	bytes, err := ioutil.ReadFile(jwtm.PubKeyPath)
	if err != nil {
		return nil, err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		return nil, err
	}
	jwtm.pubKey = key

	if jwtm.HeaderName == "" {
		jwtm.HeaderName = "Authorization"
	}
	if jwtm.HeaderPrefix == "" {
		jwtm.HeaderPrefix = "Bearer"
	}
	return jwtm, nil
}

type MapClaims = map[string]interface{}

func (jwtm *JWTMiddleware) TokenValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := jwtm.GetClaimsFromJWT(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "Not Authorized")
			c.Abort()
			return
		}
		c.Set("JWT_PAYLOAD", claims)
		c.Next()
	}
}

// GetClaimsFromJWT get claims from JWT token
func (jwtm *JWTMiddleware) GetClaimsFromJWT(c *gin.Context) (MapClaims, error) {
	token, err := jwtm.VerifyToken(c)
	if err != nil {
		return nil, err
	}

	//Set back Auth Header just in case it's needed
	if v, ok := c.Get("JWT_TOKEN"); ok {
		c.Header(jwtm.HeaderName, jwtm.HeaderPrefix+" "+v.(string))
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}
	return claims, nil
}

//VerifyToken verifies the token is valid and signed with the correct key
func (jwtm *JWTMiddleware) VerifyToken(c *gin.Context) (*jwt.Token, error) {
	tokenString, err := jwtm.jwtFromHeader(c)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, err
		}
		// save token string if valid
		c.Set("JWT_TOKEN", tokenString)

		return jwtm.pubKey, nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (jwtm *JWTMiddleware) jwtFromHeader(c *gin.Context) (string, error) {
	authHeader := c.Request.Header.Get(jwtm.HeaderName)
	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == jwtm.HeaderPrefix) {
		return "", ErrInvalidAuthHeader
	}
	return parts[1], nil
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(c *gin.Context) MapClaims {
	claims, exists := c.Get("JWT_PAYLOAD")
	if !exists {
		return make(MapClaims)
	}

	return claims.(MapClaims)
}

// ExtractClaimsFromToken help to extract the JWT claims from token
func ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

// GetToken help to get the JWT token string
func GetToken(c *gin.Context) string {
	token, exists := c.Get("JWT_TOKEN")
	if !exists {
		return ""
	}

	return token.(string)
}
