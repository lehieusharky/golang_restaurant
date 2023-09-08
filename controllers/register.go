package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"restaurant_management/models"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// định nghĩa biến validate dùng thư viện validator. Thư viện sử dụng để kiểm tra tính hợp lệ của dữ liệu
var validate = validator.New()

// hàm dùng để hash mật khẩu người dùng trước khi lưu vào cơ sở dữ liệu , sử dụng thư viện bcrypt để hash
func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

// Hàm Register là một middleware của GIN được dùng để xử dụng xử lý đăng nhập, ban đầu khởi tạo context 100s
// defer cancel() để đảm bảo context sẽ được hủy sau khi hàm kết thúc
// khai báo user là dữ liệu đăng nhập được gửi từ yêu cầu,
// c.BindJSON(&user) Nếu có lỗi trong quá trình đọc dữ liệu JSON từ yêu cầu,
// Nó sẽ trả về một lỗi với mã trạng thái "BadRequest" và thông báo lỗi tương ứng.
// Kiểm tra xem đã tồn tại người dùng nào trong cơ sở dữ liệu có cùng địa chỉ email (user.Email) hay chưa.
// Nếu có lỗi trong quá trình kiểm tra hoặc email đã tồn tại, nó trả về một lỗi với thông báo tương ứng.
// nếu không có lỗi trong bước trước đó, HashPassword để hash mật khẩu người dùng và lưu nó vào biến user.Password.
// Thiết lập các trường cho đối tượng Created_at, Updated_at, ID, userID
// thêm dữ liệu người dùng vào cơ sở dữ liệu bằng cách gọi userCollection.InsertOne.
// Nếu có lỗi trong quá trình này, nó trả về một lỗi với thông báo tương ứng.
// Cuối cùng trả về một phản hồi thành công với mã trạng thái "OK" và thông báo "register successfully".
func Register() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel() // Defer cancel() at the beginning

		var user models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking for the email"})
			return
		}

		password := HashPassword(*user.Password)
		user.Password = &password

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this email already exists"})
			return // Return after sending the response
		}

		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		_, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusOK,
			"message":"register successfully",
		})
	}
}
