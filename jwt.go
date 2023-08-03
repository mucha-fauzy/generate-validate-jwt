package main

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	secretKey      = []byte("secret")
	tokenExpiresIn = time.Hour * 24
)

// GenerateJWT generates a new JWT token for a given user ID.
func GenerateJWT(userID string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	// Set token claims (payload).
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(tokenExpiresIn).Unix()

	// Generate the token with the secret key.
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateJWT validates a given JWT token and returns the user ID if valid.
func ValidateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["user_id"].(string)
		if !ok {
			return "", fmt.Errorf("invalid token")
		}
		return userID, nil
	}

	return "", fmt.Errorf("invalid token")
}

func main() {
	userID := "user123"
	token, err := GenerateJWT(userID)
	if err != nil {
		fmt.Println("Error generating token:", err)
		return
	}
	fmt.Println("Generated JWT token:", token)

	// Simulating token validation
	validateUserID, err := ValidateJWT(token)
	if err != nil {
		fmt.Println("Error validating token:", err)
		return
	}
	fmt.Println("Validated User ID:", validateUserID)
}
