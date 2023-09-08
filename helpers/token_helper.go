package helper

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"restaurant_management/database"

	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Định nghĩa kiểu dữ liệu mới là SignedDetails (là một kiểu dữ liệu tùy chỉnh)
// SignedDetails có kiểu dữ liệu cơ bản là một struct
// Dùng để lưu trữ dùng để lưu trữ thông tin một người dùng cùng với
// jwt.StandardClaims là thông tin tiêu chuẩn của JWT 
// jwt.StandardClaims cũng là một struct được nhúng vào SignedDetails
type SignedDetails struct{
	Email 		string
	First_name 	string
	Last_name 	string
	Uid 		string
	User_type	string
	jwt.StandardClaims 
}

// Khởi tạo biến userCollection là một con trỏ tới collection có tên là "user"
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

// Khởi tạo khóa bảo mật lấy giá trị từ biến môi trường có tên là "SECRET_KEY"
var SECRET_KEY string = os.Getenv("SECRET_KEY")

// Hàm dùng để tạo Token dựa trên các đối số được lấy từ database khi tiến hành đăng nhập
// claims và refreshClaims là con trỏ đến một SignedDetails
// với claims chứa thông tin của người dùng đang được đăng nhập, và một token (token chính (JWT))
// và refreshClaims chứa thông tin của một token mới (token cập nhật)
// Việc lưu trữ 2 Claims cho phép quản lý giờ chết (hạn chót) của token riêng biệt
// 2 token được tạo ra bởi thuật toán signingMethodHS25 để ký và mã hóa token,
// sau đó các thông tin của claim và refreshToken được đặt và token tương ứng (token và refreshToken) 
// Dùng giá trị của SECRET_KEY để ký token, được chuyển thành chuỗi bằng SignedString([]byte(SECRET_KEY))
// Token hiện tại được cài thời gian là 24h kể từ thời điểm hiện tại
// RefreshToken được cài thời gian là 168h (1 tuần) kể từ thời điểm hiện tại
// Nếu có bất kỳ lỗi nào trong quá trình tạo token sẽ log Lỗi
// Trả về token, refreshToken và err (nếu có)
func GenerateAllTokens(email string, firstName string, lastName string, userType string, uid string) (signedToken string, signedRefreshToken string, err error){
	claims := &SignedDetails{
		Email : email,
		First_name: firstName,
		Last_name: lastName,
		Uid : uid,
		User_type: userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}

	token ,err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return 
	}

	return token, refreshToken, err
}

// Hàm dùng để kiểm tra và xác thực tính hợp lệ của JWT và trích xuất thông tin từ JWT nếu JWT là hợp lệ
// ParseWithClaims là hàm để phân tích chuỗi JWT.
// với đối số là chuỗi signedToken được lấy từ ..(del biết nữa, từ từ)..
// hàm phân tích chuỗi signedToken để trở thành 1 *jwt.Token sau đó gán thông tin đó vào &SignedDetail{} đã được khởi tạo.
// &SignedDetail{} có nghĩa là khởi tạo một đối tượng của kiểu SignedDetails và trả về một con trỏ đến đối tượng đó
// func(token *jwt.Token)(interface{}, error){} khai báo một hàm nhận đối số là con trỏ token được truyền từ ParseWithClaims
// Và trả về 2 giá trị (interface{}, error), interface{} là kiểu trả về của khóa key
// (interface{} để có thể trả về khóa ở nhiều định dạng chẳng hạn như một mảng []byte
// Nếu hàm lấy khóa thành công, error nhận trả về nil 
// Hàm trả về một mảng byte ([]byte) chứa giá trị của biến SECRET_KEY như một khóa
// để kiểm tra chữ ký của JWT. Điều này có nghĩa rằng JWT sẽ được kiểm tra tính hợp lệ
// bằng cách so sánh chữ ký của nó với giá trị của biến SECRET_KEY. Nếu chữ ký khớp, JWT được coi là hợp lệ.
// hàm sử dụng token.Claims để truy cập phần thông tin (payload) của JWT
// Thông tin này được truy cập dưới dạng một con trỏ đến SignedDetails.
// Hàm kiểm tra xem việc truy cập này có thành công không bằng cách kiểm tra kiểu (ok) và gán kết quả vào biến claims
// Cuối cùng, hàm kiểm tra xem token có hợp lệ hay không bằng cách so sánh thời gian hết hạn (ExpiresAt) của token
// với thời gian hiện tại (time.Now().Local().Unix()).
// Nếu thời gian hết hạn của token đã qua (lớn hơn thời gian hiện tại),
// hàm trả về thông báo lỗi "token is expired" và thoát khỏi hàm.
// Nếu trong quá trình xác thực không thành thì sẽ trả về lỗi thông qua biến msg và thoát khỏi hàm.
// Ngược lại trích xuất thông tin từ JWT nếu JWT là hợp lệ.
func ValidateToken(signedToken string) (claims *SignedDetails, msg string){

	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},

		func(token *jwt.Token)(interface{}, error){
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		msg=err.Error()
		return
	}

	claims, ok:= token.Claims.(*SignedDetails)
	if !ok{
		msg = fmt.Sprintf("the token is invalid")
		msg = err.Error()
		return
	}

	if claims.ExpiresAt < time.Now().Local().Unix(){
		msg = fmt.Sprintf("token is expired")
		msg = err.Error()
		return
	}
	return claims, msg
}

// Hàm hực hiện việc cập nhật token chính và token cập nhật
// hàm bắt đầu với việc khởi tạo một context với thời gian tối đa là 100 giây.
// Context này được sử dụng cho các thao tác với cơ sở dữ liệu
// biến updateObj có kiểu là primitive.D (đại diện cho các tài liệu BSON (Binary JSON) trong MongoDB).
// updateObj chứa các thông tin cần được cập nhật hoặc chèn vào tài liêu (2 cặp key-value (bson.E) token:signedToken và refreshToken:signedRefreshToken)
// Thời gian tạo 2 token mới được định dạng nó theo chuẩn RFC3339. Sau đó, nó thêm trường "updated_at" với giá trị thời gian hiện tại vào updateObj
// Biến upsert được đặt thành true, đây là một tùy chọn để cho biết nếu không tìm thấy tài liệu phù hợp
// với điều kiện tìm kiếm (filter) thì hàm sẽ thực hiện thêm tài liệu mới.
// filter được sử dụng để chỉ định điều kiện tìm kiếm, trong trường hợp này, là "user_id" phải trùng với userId
// userCollection.UpdateOne thực hiện việc cập nhật (hoặc chèn mới nếu không tìm thấy tài liệu) trong bộ sưu tập userCollection.
// Thao tác này cập nhật tài liệu mà có điều kiện tìm kiếm là "user_id" phải trùng với userId
// Dữ liệu cập nhật được đặt trong một tài liệu BSON với $set operator để cập nhật các trường đã chỉ định trong updateObj. 
// Thư viện MongoDB cũng sử dụng tùy chọn Upsert để cho biết liệu hàm nên thêm tài liệu mới nếu không tìm thấy tài liệu phù hợp
// hàm defer cancel() được sử dụng để đảm bảo rằng ngữ cảnh (context) sẽ bị hủy sau khi hàm thực hiện xong.
// Nếu có bất kỳ lỗi nào trong quá trình thực hiện thao tác cập nhật hoặc chèn tài liệu, hàm sẽ ghi log thông báo lỗi và kết thúc thực thi.
func UpdateAllTokens(signedToken string, signedRefreshToken string, userId string){
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var updateObj primitive.D

	updateObj = append(updateObj, bson.E{Key: "token", Value: signedToken})
	updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: signedRefreshToken})

	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{Key: "updated_at", Value: Updated_at})

	upsert := true
	filter := bson.M{"user_id":userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj},
		},
		&opt,
	)

	defer cancel()

	if err!=nil{
		log.Panic(err)
		return
	}
	return
}