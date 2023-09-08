package middleware

import (
	"fmt"
	"net/http"
	helper "restaurant_management/helpers"

	"github.com/gin-gonic/gin"
)

// middleware kiểm tra xem token đã được gửi từ client (clientToken) có rỗng không. 
// Nếu không có token hoặc token rỗng, middleware trả về một lỗi và kết thúc xử lý yêu cầu bằng cách gọi c.Abort().
// Nó sử dụng phản hồi HTTP với mã trạng thái "InternalServerError" (mã trạng thái 500) và trả về một JSON object chứa thông báo lỗi.
// Nếu token tồn tại và không rỗng, middleware gọi hàm ValidateToken(clientToken) để xác thực token.
// Nếu hàm này trả về một thông báo lỗi (khác rỗng),
// nghĩa là token không hợp lệ, middleware cũng trả về lỗi và kết thúc xử lý yêu cầu.
// Nếu token được xác thực thành công, middleware tiếp tục xử lý yêu cầu và đặt các giá trị từ claims của token vào context của yêu cầu Gin bằng c.Set().
// Điều này cho phép các xử lý tiếp theo trong chuỗi middleware hoặc các xử lý API endpoints sau đó có thể truy cập thông tin từ claims của token
// Cuối cùng, middleware gọi c.Next() để chuyển quyền kiểm soát sang middleware hoặc xử lý tiếp theo trong chuỗi middleware hoặc để xử lý API endpoint chính
func Authenticate() gin.HandlerFunc{
	return func(c *gin.Context){
		clientToken := c.Request.Header.Get("token")
		if clientToken == ""{
			c.JSON(http.StatusInternalServerError, gin.H{"error":fmt.Sprintf("No Authorization header provided")})
			c.Abort()
			return
		}

		claims, err := helper.ValidateToken(clientToken)
		if err !="" {
			c.JSON(http.StatusInternalServerError, gin.H{"error":err})
			c.Abort()
			return
		}
		c.Set("email", claims.Email)
		c.Set("first_name", claims.First_name)
		c.Set("last_name", claims.Last_name)
		c.Set("uid",claims.Uid)
		c.Set("user_type", claims.User_type)
		c.Next()
	}
}