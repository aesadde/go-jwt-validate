package main

import (
	"log"
	"net/http"

	"github.com/aesadde/go-jwt-validate"
	"github.com/gin-gonic/gin"
)

func helloHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	c.JSON(200, claims)
}

func main() {

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	authMiddleware, err := jwt.NewJWTValidationMiddleware(&jwt.JWTMiddleware{
		PubKeyPath:   "./key.pub",
		HeaderName:   "",
		HeaderPrefix: "",
	})
	if err != nil {
		log.Fatalf("Unable to create new middleware  -- %v", err.Error())
	}

	auth := r.Group("/auth")
	auth.Use(authMiddleware.TokenValidationMiddleware())
	{
		auth.GET("/hello", helloHandler)
	}
	if err := http.ListenAndServe(":8000", r); err != nil {
		log.Fatal(err)
	}
}
