package main

import (
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"
	"github.com/sampingan/RestfullJWT/common"
	"github.com/sampingan/RestfullJWT/config"
	"github.com/sampingan/RestfullJWT/controllers"
	"github.com/sampingan/RestfullJWT/middleware"
	"github.com/sampingan/RestfullJWT/structs"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

// type UserInfo struct {
// 	Username string
// 	Email    string
// }

var identityKey = "id"
var credential structs.UserCredential

func adminInfoHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	c.JSON(200, gin.H{
		"username": claims["id"],
		"email":    claims["email"],
		"role":     claims["role"],
		"text":     "This endpoint only accessed by admin",
	})
}

func freeInfoHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	c.JSON(200, gin.H{
		"username": claims["id"],
		"email":    claims["email"],
		"role":     claims["role"],
		"text":     "Everyone can access me",
	})
}

func proInfoHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	c.JSON(200, gin.H{
		"username": claims["id"],
		"email":    claims["email"],
		"role":     claims["role"],
		"text":     "I'm a pro user",
	})
}

func main() {
	db := config.DBInit()
	inDB := &controllers.InDB{DB: db}

	port := os.Getenv("PORT")
	r := gin.Default()

	if port == "" {
		port = "8000"
	}

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("your secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*structs.UserCredential); ok {
				return jwt.MapClaims{
					identityKey: v.Username,
					"email":     v.Email,
					"role":      v.Role,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &structs.UserCredential{
				Username: claims["id"].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals login
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			username := loginVals.Username
			password := loginVals.Password

			var (
				user structs.User
			)

			auth, user := common.Login(username, password)

			if !auth {
				return nil, jwt.ErrFailedAuthentication
			}

			return &structs.UserCredential{
				Username: user.Username,
				Email:    user.Email,
				Role:     user.Role,
			}, nil

		},
		LoginResponse: func(c *gin.Context, code int, message string, exp time.Time) {
			c.JSON(code, gin.H{
				"token": message,
				"time":  exp,
				// "result": c,
			})
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if v, ok := data.(*structs.UserCredential); ok && v.Username != "" {
				return true
			}

			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},

		TokenLookup: "header: Authorization, query: token, cookie: jwt",

		TokenHeadName: "Bearer",

		// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
		TimeFunc: time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.POST("/login", authMiddleware.LoginHandler)
	r.POST("/register", inDB.CreateUser)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	admin := r.Group("/admin")
	// Refresh time can be longer than token timeout
	// admin.GET("/refresh_token", authMiddleware.RefreshHandler)
	admin.Use(authMiddleware.MiddlewareFunc())
	admin.Use(middleware.IsAdmin())
	{
		admin.GET("/info", adminInfoHandler)
	}

	// all can access
	r.GET("/info", authMiddleware.MiddlewareFunc(), freeInfoHandler)

	// only pro and admin
	pro := r.Group("/pro")
	pro.Use(authMiddleware.MiddlewareFunc())
	pro.Use(middleware.IsPro())
	{
		pro.GET("/info", proInfoHandler)
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
