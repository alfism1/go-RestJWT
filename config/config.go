package config

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/sampingan/RestfullJWT/structs"
)

// DBInit create connection to database
func DBInit() *gorm.DB {
	db, err := gorm.Open("mysql", "root:@/godb?charset=utf8&parseTime=True&loc=Local")
	// defer db.Close()
	if err != nil {
		panic("failed to connect to database")
	}

	db.AutoMigrate(
		structs.User{},
	)
	return db
}
