package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"net/http"
	repo "scaha_micro_member/repository"
	"time"
)

var jwtKey = []byte("my_secret_key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}


//
type Claims struct {
	UserName string `json:"username"`
	UserId  int
	AdminRole bool  `json:"AdminRole"`
	jwt.StandardClaims
}

func Signin(dao repo.DAO) func(echo.Context) error {
	return func(c echo.Context) error {
		var creds Credentials
		// Get the JSON body and decode into credentials
		err := json.NewDecoder(c.Request().Body).Decode(&creds)
		if err != nil {
			// If the structure of the body is wrong, return an HTTP error
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		// Get the expected password from our in memory map
		expectedPassword, ok := users[creds.Username]

		// If a password exists for the given user
		// AND, if it is the same as the password we received, the we can move ahead
		// if NOT, then we return an "Unauthorized" status
		if !ok || expectedPassword != creds.Password {
			return c.String(http.StatusUnauthorized, "You are not authorized")
		}

		// Declare the expiration time of the token
		// here, we have kept it as 5 minutes
		expirationTime := time.Now().Add(5 * time.Minute)
		// Create the JWT claims, which includes the username and expiry time
		claims := &Claims{
			UserName: creds.Username,
			StandardClaims: jwt.StandardClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: expirationTime.Unix(),
			},
			UserId: 1234,
		}

		// Declare the token with the algorithm used for signing, and the claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Create the JWT string
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			// If there is an error in creating the JWT return an internal server error
			return c.String(http.StatusInternalServerError, "Something went horribly wrong")
		}

		// Finally, we set the client cookie for "token" as the JWT we just generated
		// we also set an expiry time which is the same as the token itself
		c.SetCookie(&http.Cookie{
			Name:    "jwt",
			Value:   tokenString,
			Expires: expirationTime,
		})

		log.Info("Claims:%v", claims)
		return c.String(http.StatusOK, "write a cookie")
	}
 }

func Validate(dao repo.DAO) func(echo.Context) error {
	// We can obtain the session token from the requests cookies, which come with every request
	return func(c echo.Context) error {

		cook, err := c.Cookie("jwt")
		if err != nil {
			if err == http.ErrNoCookie {
				// If the cookie is not set, return an unauthorized status
				return c.String(http.StatusUnauthorized, "You are not authorized")
			}
			// For any other type of error, return a bad request status
			return c.String(http.StatusBadRequest, "Bad Request")
		}

		// Get the JWT string from the cookie
		tknStr := cook.Value

		// Initialize a new instance of `Claims`
		claims := &Claims{}

		// Parse the JWT string and store the result in `claims`.
		// Note that we are passing the key in this method as well. This method will return an error
		// if the token is invalid (if it has expired according to the expiry time we set on sign in),
		// or if the signature does not match
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				return c.String(http.StatusUnauthorized, "You are not authorized")
			}
			return c.String(http.StatusBadRequest, "Bad Request")
		}
		if !tkn.Valid {
			return c.String(http.StatusUnauthorized, "You are not authorized")
		}
		// Finally, return the welcome message to the user, along with their
		// username given in the token
		log.Info("Claims:%v", claims)
		return c.String (http.StatusOK, fmt.Sprintf("Welcome %s!", claims.UserName))
	}
}


func RefreshToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
		cook, err := c.Cookie("jwt")
		if err != nil {
			if err == http.ErrNoCookie {
				// If the cookie is not set, return an unauthorized status
				return c.String(http.StatusUnauthorized, "You are not authorized")
			}
			// For any other type of error, return a bad request status
			return c.String(http.StatusBadRequest, "Bad Request A")
		}

		// Get the JWT string from the cookie
		tknStr := cook.Value

		// Initialize a new instance of `Claims`
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				return c.String(http.StatusUnauthorized, fmt.Sprintf("You are Not Authorized %v:%s:%v", err, err.Error(),jwt.ErrSignatureInvalid))
			}
			return c.String(http.StatusBadRequest, fmt.Sprintf("Bad Request B %v:%s:%v", err, err.Error(),jwt.ErrSignatureInvalid))
		}
		if !tkn.Valid {
			return c.String(http.StatusUnauthorized, "You are not authorized")
		}
		// (END) The code uptil this point is the same as the first part of the `Welcome` route

		// We ensure that a new token is not issued until enough time has elapsed
		// In this case, a new token will only be issued if the old token is within
		// 30 seconds of expiry. otherwise.. leave everything be
		if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
			return next(c)
		}

		// Now, create a new token for the current use, with a renewed expiration time
		expirationTime := time.Now().Add(5 * time.Minute)
		claims.ExpiresAt = expirationTime.Unix()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Crazy ass internal error")
		}

		c.SetCookie(&http.Cookie{
			Name:    "jwt",
			Value:   tokenString,
			Expires: expirationTime,
		})
		return next(c)
	}
}
func Refresh(dao repo.DAO) func(echo.Context) error {
	// We can obtain the session token from the requests cookies, which come with every request
	return func(c echo.Context) error {

		// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
		cook, err := c.Cookie("jwt")
		if err != nil {
			if err == http.ErrNoCookie {
				// If the cookie is not set, return an unauthorized status
				return c.String(http.StatusUnauthorized, "You are not authorized")
			}
			// For any other type of error, return a bad request status
			return c.String(http.StatusBadRequest, "Bad Request A")
		}

		// Get the JWT string from the cookie
		tknStr := cook.Value

		// Initialize a new instance of `Claims`
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				return c.String(http.StatusUnauthorized, fmt.Sprintf("You are Not Authorized %v:%s:%v", err, err.Error(),jwt.ErrSignatureInvalid))
			}
			return c.String(http.StatusBadRequest, fmt.Sprintf("Bad Request B %v:%s:%v", err, err.Error(),jwt.ErrSignatureInvalid))
		}
		if !tkn.Valid {
			return c.String(http.StatusUnauthorized, "You are not authorized")
		}
		// (END) The code uptil this point is the same as the first part of the `Welcome` route

		// We ensure that a new token is not issued until enough time has elapsed
		// In this case, a new token will only be issued if the old token is within
		// 30 seconds of expiry. Otherwise, return a bad request status
		if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
			return c.String(http.StatusBadRequest, "Bad Request C" )
		}

		// Now, create a new token for the current use, with a renewed expiration time
		expirationTime := time.Now().Add(5 * time.Minute)
		claims.ExpiresAt = expirationTime.Unix()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Crazy ass internal error")
		}

		c.SetCookie(&http.Cookie{
			Name:    "jwt",
			Value:   tokenString,
			Expires: expirationTime,
		})

		return c.String(http.StatusOK, "write a cookie")
	}
}
