package controllers

import (
	"context"
	"fmt"
	"net/http"
	helper "restaurant_management/helpers"
	"restaurant_management/models"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

// Hàm xác thực mật khẩu là đúng với dữ liệu đã có hay không
// So sánh mật khẩu được cung cấp với mật khẩu đã được cung cấp
// đúng thì trả về true, sai biến msg được gán lỗi
func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email of password is incorrect")
		check = false
	}
	return check, msg
}

// Hàm Login là một middleware của GIN được dùng để xử dụng xử lý đăng nhập, ban đầu khởi tạo context 100s
// defer cancel() để đảm bảo context sẽ được hủy sau khi hàm kết thúc
// khai báo user là dữ liệu đăng nhập được gửi từ yêu cầu, fouderUser chứa thông tin người dùng được tìm thấy trong cơ sở dữ liệu
// c.BindJSON(&user) Nếu có lỗi trong quá trình đọc dữ liệu JSON từ yêu cầu,
// Nó sẽ trả về một lỗi với mã trạng thái "BadRequest" và thông báo lỗi tương ứng. 
// Sử dụng userCollection.FindOne để tìm người dùng dựa trên địa chỉ user.Email. Gọi hàm VerifyPassword để xác minh mật khẩu
// middleware kiểm tra xem người dùng đã được tìm thấy hay chưa (dựa trên foundUser.Email).
// Nếu không tìm thấy, nó trả về một lỗi "user not found".
// Nếu tất cả các kiểm tra trước đó thành công, middleware sử dụng hàm helper.GenerateAllTokens để tạo token xác thực và token cập nhật cho người dùng.
// Token được tạo và sau đó được cập nhật trong cơ sở dữ liệu bằng cách gọi helper.UpdateAllTokens
// trả về một phản hồi thành công với mã trạng thái "OK" và chứa thông tin về token và refresh token trong phản hồi JSON.
func Login() gin.HandlerFunc{
	return func(c *gin.Context){
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return 
		}

		err := userCollection.FindOne(ctx, bson.M{"email":user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error":"email or password is incorrect"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordIsValid != true{
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error":"user not found"})
		}
		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id":foundUser.User_id}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":http.StatusOK,
			"message": "Login successfully",
			"token": foundUser.Token,
			"refresh token": foundUser.Refresh_token})
	}
}