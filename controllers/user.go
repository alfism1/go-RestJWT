package controllers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sampingan/RestfullJWT/structs"
	"golang.org/x/crypto/bcrypt"
)

type UserData struct {
	ID        uint
	Username  string
	Email     string
	Role      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (idb *InDB) GetAllUser(c *gin.Context) {
	var (
		users  []UserData
		result gin.H
	)

	idb.DB.Table("users").Select("id, username, email, role, created_at, updated_at").Find(&users)
	if len(users) <= 0 {
		result = gin.H{
			"result": nil,
			"count":  0,
		}
	} else {
		result = gin.H{
			"result": users,
			"count":  len(users),
		}
	}

	c.JSON(http.StatusOK, result)
}

func (idb *InDB) GetUser(c *gin.Context) {
	var (
		user   UserData
		result gin.H
	)

	id := c.Param("id")
	err := idb.DB.Table("users").Select("id, username, email, role, created_at, updated_at").Where("id=?", id).Find(&user).Error
	if err != nil {
		result = gin.H{
			"result": nil,
			"count":  0,
		}
	} else {
		result = gin.H{
			"result": user,
			"count":  1,
		}
	}

	c.JSON(http.StatusOK, result)
}

// CreateUser - create new data to the database
func (idb *InDB) CreateUser(c *gin.Context) {
	var (
		user   structs.User
		result gin.H
	)
	username := c.PostForm("username")
	password := c.PostForm("password")
	email := c.PostForm("email")
	role := c.PostForm("role")
	user.Username = username
	user.Password, _ = hashPassword(password)
	user.Email = email
	user.Role = role
	idb.DB.Create(&user)
	result = gin.H{
		"result": user,
	}
	c.JSON(http.StatusOK, result)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
