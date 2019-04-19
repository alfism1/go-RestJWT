package structs

import "github.com/jinzhu/gorm"

type User struct {
	gorm.Model
	Username string
	Password string
	Email    string
	Role     string
}

type UserCredential struct {
	Username string
	Email    string
	Role     string
}
