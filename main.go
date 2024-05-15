package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	user_controller "user_auth_with_go/controllers"
	"user_auth_with_go/db"
	authMiddleware "user_auth_with_go/middleware"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter DB user: ")
	dbUser, _ := reader.ReadString('\n')
	dbUser = strings.TrimSpace(dbUser)

	fmt.Print("Enter DB password: ")
	dbPassword, _ := reader.ReadString('\n')
	dbPassword = strings.TrimSpace(dbPassword)

	fmt.Print("Enter DB name: ")
	dbName, _ := reader.ReadString('\n')
	dbName = strings.TrimSpace(dbName)

	fmt.Print("Enter DB host (default: localhost): ")
	dbHost, _ := reader.ReadString('\n')
	dbHost = strings.TrimSpace(dbHost)
	if dbHost == "" {
		dbHost = "localhost"
	}

	fmt.Print("Enter DB port (default: 5432): ")
	dbPort, _ := reader.ReadString('\n')
	dbPort = strings.TrimSpace(dbPort)
	if dbPort == "" {
		dbPort = "5432"
	}

	fmt.Print("Enter server port (default: 1323): ")
	serverPort, _ := reader.ReadString('\n')
	serverPort = strings.TrimSpace(serverPort)
	if serverPort == "" {
		serverPort = "1323"
	}

	// Construct the connection string
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", dbUser, dbPassword, dbHost, dbPort, dbName)

	// Initialize database connection
	db.Init(connStr)

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/register", user_controller.RegisterUser)
	e.POST("/login", user_controller.LoginUser)

	userGroup := e.Group("/user")
	userGroup.Use(authMiddleware.JWTMiddleware)
	userGroup.GET("/me", user_controller.GetUserInfo)
	userGroup.PUT("/update", user_controller.UpdateUserInfo)
	userGroup.PUT("/update-password", user_controller.UpdateUserPassword)

	adminGroup := e.Group("/admin")
	adminGroup.Use(authMiddleware.JWTMiddleware, authMiddleware.AdminMiddleware)
	adminGroup.PUT("/update-role", user_controller.UpdateUserRole)
	adminGroup.DELETE("/:id", user_controller.DeleteUser)
	adminGroup.GET("/all", user_controller.GetAllUsers)

	e.Logger.Fatal(e.Start(":" + serverPort))
}
