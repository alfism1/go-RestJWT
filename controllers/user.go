package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sampingan/RestfullJWT/structs"
	"golang.org/x/crypto/bcrypt"
)

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
