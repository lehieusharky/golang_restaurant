package helper

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// Kiểm tra loại User có phải là ADMIN hay không?
func CheckUserType(c *gin.Context, role string) (err error){
	userType := c.GetString("user_type")
	err = nil
	if userType != role {
		err = errors.New("Unauthorized to access this resource")
		return err
	}
	return err
}

// Kiểm tra ID user và ID có trùng với tài nguyên hay không và chặn truy cập tài nguyên nếu là USER 
func MatchUserTypeToUid(c *gin.Context, userId string) (err error){
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil

	if userType == "USER" && uid != userId {
		err = errors.New("Unauthorized to access this resource")
		return err
	}
	// Kiểm tra loại User có phải là ADMIN hay không?
	err = CheckUserType(c, userType)
	return err
}