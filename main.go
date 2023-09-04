package main

import (
	"log"
	"os"

	// "restaurant_management/database"
	"restaurant_management/routes"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	// "go.mongodb.org/mongo-driver/mongo"
)

// var foodCollection *mongo.Collection = database.OpenCollection(database.Client, "food")


func main() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal("Error loading .env file")
	}
	port := os.Getenv("PORT")

	if port==""{
		port="8000"
	}

	router := gin.New()
	router.Use(gin.Logger())

	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	// routes.UserRoutes(router)
	// router.Use(middleware.Authentication())

	// routes.FoodRoutes(router)
	// routes.MenuRoutes(router)
	// routes.TableRoutes(router)
	// routes.OrderRoutes(router)
	// routes.OrderItemRoutes(router)
	// routes.InvoiceRoutes(router)


	// router được khởi chạy và lắng nghe trên cổng được xác định bởi biến port
	router.Run(":" + port)
}