package main

import (
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"
	"github.com/sampingan/RestfullJWT/config"
	"github.com/sampingan/RestfullJWT/structs"
	"golang.org/x/crypto/bcrypt"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var identityKey = "id"

func helloHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	// fmt.Println(claims)
	c.JSON(200, gin.H{
		"userID":   claims["id"],
		"userName": user.(*UserInfo).Username,
		"text":     "Hello World.",
	})
}

type UserInfo struct {
	Username string
	Email    string
}

func main() {
	db := config.DBInit()
	// _ = &controllers.InDB{DB: db}

	port := os.Getenv("PORT")
	r := gin.Default()
	// r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8000"
	}

	var usr UserInfo
	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("your secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*UserInfo); ok {
				return jwt.MapClaims{
					identityKey: v.Username,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &UserInfo{
				Username: claims["id"].(string),
				Email:    usr.Email,
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals login
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			username := loginVals.Username
			password := loginVals.Password
			// fmt.Println(password)

			var (
				user structs.User
			)

			err := db.Select("username, email, password").Where("username = ?", username).First(&user).Error
			if err != nil {
				return nil, jwt.ErrFailedAuthentication
			}
			// check password
			if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
				// If the two passwords don't match, return a 401 status
				return nil, jwt.ErrFailedAuthentication
			}

			usr = UserInfo{
				user.Username,
				user.Email,
			}
			return &UserInfo{
				Username: username,
				Email:    user.Email,
			}, nil

		},
		LoginResponse: func(c *gin.Context, code int, message string, exp time.Time) {
			// fmt.Println(usr)
			c.JSON(code, gin.H{
				"message": message,
				"time":    exp,
				"result":  usr,
			})
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			// fmt.Println(c.GetHeader("Authorization"))
			if v, ok := data.(*UserInfo); ok && v.Username != "" {
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

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	auth := r.Group("/auth")
	// Refresh time can be longer than token timeout
	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/hello", helloHandler)
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
