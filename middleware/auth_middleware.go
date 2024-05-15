package auth_middleware

import (
	"net/http"

	user_model "user_auth_with_go/models"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

var jwtKey = []byte("testing123")

func JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	config := echojwt.Config{
		SigningKey: jwtKey,
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(user_model.JWTClaims)
		},
	}

	return echojwt.WithConfig(config)(next)
}

func AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*user_model.JWTClaims)

		if claims.Role != 1 {
			return c.JSON(http.StatusForbidden, "You don't have permission to access this resource")
		}

		return next(c)
	}
}
