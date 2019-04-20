package common

import (
	"github.com/sampingan/RestfullJWT/config"
	"github.com/sampingan/RestfullJWT/structs"
	"golang.org/x/crypto/bcrypt"
)

func Login(username string, password string) (bool, structs.User) {
	// fmt.Println("Ora popo")
	db := config.DBInit()

	var (
		user structs.User
	)
	err := db.Select("username, email, password, role").Where("username = ?", username).First(&user).Error
	if err != nil {
		return false, user
	}
	// check password
	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		// If the two passwords don't match, return a 401 status
		return false, user
	}

	return true, user
}
