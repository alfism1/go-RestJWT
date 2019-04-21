package middleware

import (
	jwt "github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"
)

func IsAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)

		if claims["role"] != "admin" {
			c.JSON(401, gin.H{
				"code":    401,
				"message": "Need admin permission",
			})
			c.Abort()
		}
	}
}

func IsPro() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)

		if claims["role"] != "pro" {
			c.JSON(401, gin.H{
				"code":    401,
				"message": "Need pro user",
			})
			c.Abort()
		}
	}
}
