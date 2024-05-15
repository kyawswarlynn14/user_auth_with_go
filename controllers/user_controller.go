package user_controller

import (
	"database/sql"
	"net/http"
	"time"

	"user_auth_with_go/db"
	user_model "user_auth_with_go/models"

	"github.com/asaskevich/govalidator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("testing123")

func RegisterUser(c echo.Context) error {
	user := new(user_model.User)
	if err := c.Bind(user); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	if !govalidator.IsEmail(user.Email) {
		return c.JSON(http.StatusBadRequest, "Invalid email format")
	}
	if len(user.Password) < 6 {
		return c.JSON(http.StatusBadRequest, "Password should be at least 6 characters")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	user.Password = string(hashedPassword)

	_, err = db.DB.Exec("INSERT INTO users (name, email, password) VALUES ($1, $2, $3)", user.Name, user.Email, user.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusCreated, "User registered successfully")
}

func LoginUser(c echo.Context) error {
	user := new(user_model.User)
	if err := c.Bind(user); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	storedUser := new(user_model.User)
	err := db.DB.QueryRow("SELECT id, name, email, password, role FROM users WHERE email=$1", user.Email).Scan(&storedUser.ID, &storedUser.Name, &storedUser.Email, &storedUser.Password, &storedUser.Role)
	if err == sql.ErrNoRows || bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password)) != nil {
		return c.JSON(http.StatusUnauthorized, "Invalid email or password")
	}

	claims := &user_model.JWTClaims{
		ID:    storedUser.ID,
		Name:  storedUser.Name,
		Email: storedUser.Email,
		Role:  storedUser.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, echo.Map{
		"user":  storedUser,
		"token": tokenString,
	})
}

func GetUserInfo(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*user_model.JWTClaims)

	storedUser := new(user_model.User)
	err := db.DB.QueryRow("SELECT id, name, email, role FROM users WHERE id=$1", claims.ID).Scan(&storedUser.ID, &storedUser.Name, &storedUser.Email, &storedUser.Role)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, storedUser)
}

func UpdateUserInfo(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*user_model.JWTClaims)

	updatedUser := new(user_model.User)
	if err := c.Bind(updatedUser); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	_, err := db.DB.Exec("UPDATE users SET name=$1, email=$2 WHERE id=$3", updatedUser.Name, updatedUser.Email, claims.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, "User info updated successfully")
}

func UpdateUserPassword(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*user_model.JWTClaims)

	passwordData := struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}{}

	if err := c.Bind(&passwordData); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	storedPassword := ""
	err := db.DB.QueryRow("SELECT password FROM users WHERE id=$1", claims.ID).Scan(&storedPassword)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	if bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(passwordData.OldPassword)) != nil {
		return c.JSON(http.StatusUnauthorized, "Old password is incorrect")
	}

	if len(passwordData.NewPassword) < 6 {
		return c.JSON(http.StatusBadRequest, "New password should be at least 6 characters")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwordData.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	_, err = db.DB.Exec("UPDATE users SET password=$1 WHERE id=$2", hashedPassword, claims.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, "Password updated successfully")
}

func UpdateUserRole(c echo.Context) error {
	var input struct {
		ID   int `json:"id"`
		Role int `json:"role"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid input")
	}

	_, err := db.DB.Exec("UPDATE users SET role=$1 WHERE id=$2", input.Role, input.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Failed to update user role")
	}

	return c.JSON(http.StatusOK, "User role updated successfully")
}

func DeleteUser(c echo.Context) error {
	userID := c.Param("id")

	_, err := db.DB.Exec("DELETE FROM users WHERE id=$1", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, "User deleted successfully")
}

func GetAllUsers(c echo.Context) error {
	rows, err := db.DB.Query("SELECT id, name, email, role FROM users")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	defer rows.Close()

	users := []user_model.User{}
	for rows.Next() {
		var user user_model.User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Role); err != nil {
			return c.JSON(http.StatusInternalServerError, err.Error())
		}
		users = append(users, user)
	}
	return c.JSON(http.StatusOK, users)
}
