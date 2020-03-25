package main

import (
	"encoding/json"
	"fmt"
	m "github.com/davidbigelow25/scaha-entity-model"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"

	"net/http"
	"os"
	"sync"
	"time"
)

var jwtKey = []byte("my_secret_key")

//
// This handles all the sign in.
// it will check the usercode password to make sure user is authenticated
//
// and if authenticated, we will hand back a token in the cookie that has
// all the roles and clubs that member belongs to
func signin(dao DAO) func(echo.Context) error {
	return func(c echo.Context) error {

		// Let initially expire any cookie
		c.SetCookie(&http.Cookie{
			Name:    "jwt",
			Expires: time.Now().Add(-1 * time.Minute),
		})

		var creds m.Credentials
		// Get the JSON body and decode into credentials
		err := json.NewDecoder(c.Request().Body).Decode(&creds)
		if err != nil {
			// If the structure of the body is wrong, return an HTTP error
			return c.String(http.StatusBadRequest, "Bad Request: Cannot Decipher your payload")
		}

		profile, ok := dao.FindProfile(creds.Username, creds.Password)

		// If a password exists for the given user
		// AND, if it is the same as the password we received, the we can move ahead
		// if NOT, then we return an "Unauthorized" status
		if ok != nil  {
			return c.String(http.StatusUnauthorized, "You are not authorized")
		}

		// Declare the expiration time of the token
		// here, we have kept it as 5 minutes
		expirationTime := time.Now().Add(5 * time.Minute)
		// Create the JWT claims, which includes the username and expiry time
		claims := &m.Claims{
			UserName: profile.UserCode,
			ProfileId: profile.ID,
			UserId:  profile.Person.ID,
			StandardClaims: jwt.StandardClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: expirationTime.Unix(),
			},
			Roles: profile.Roles.FlattenAndMap(),
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

func signout() func(echo.Context) error {
	return func(c echo.Context) error {

		// Let initially expire any cookie
		c.SetCookie(&http.Cookie{
			Name:    "jwt",
			Expires: time.Now().Add(-1 * time.Minute),
		})
		return c.String(http.StatusOK, "Cookie Wiper")
	}
}

//
// ValidateToken:  This simply gets the cookie from the request
// and it parses
func  validatetoken(dao DAO) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

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
			claims := &m.Claims{}

			// Parse the JWT string and store the result in `claims`.
			// Note that we are passing the key in this method as well. This method will return an error
			// if the token is invalid (if it has expired according to the expiry time we set on sign in),
			// or if the signature does not match
			tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})
			if err != nil {
				if err == jwt.ErrSignatureInvalid {
					return c.String(http.StatusUnauthorized, fmt.Sprintf("You are Not Authorized %v:%s:%v", err, err.Error(), jwt.ErrSignatureInvalid))
				}
				return c.String(http.StatusBadRequest, fmt.Sprintf("Bad Request B %v:%s:%v", err, err.Error(), jwt.ErrSignatureInvalid))
			}
			if !tkn.Valid {
				return c.String(http.StatusUnauthorized, "You are not authorized")
			}

			profilesexist, err := dao.DoesProfileExist(claims.ProfileId)
			if err != nil || !profilesexist {
				return c.String(http.StatusUnauthorized, "You are not authorized: 10101")
			}

			// We ensure that a new token is not issued until enough time has elapsed
			// In this case, a new token will only be issued if the old token is within
			// 30 seconds of expiry. otherwise.. leave everything be
			if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) < 30*time.Second {

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

			}
			return next(c)
		}
	}
}

func GeneratePayload(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*m.Claims)
	return c.JSON(http.StatusOK, claims)
}

//
// Lets handle these bad boys
//
func handleRequests(dbgorm *gorm.DB) {

	//
	// lets instantiate some simple things here
	//
	ext := echo.New()      // This is the externally supported login API.  It only exposes SignIn and Sign out
	internal := echo.New() // This is the externally supported login API.  It only exposes SignIn and Sign out

	db := DAO{DB: dbgorm}

	ext.Use(middleware.Recover())
	ext.Use(middleware.Logger())

	internal.Use(middleware.Recover())
	internal.Use(middleware.Logger())

	// This is the only path that can be taken for the external
	// There is sign in.
	// TODO: Signout
	ext.POST("/signin", signin(db))   // This validates the user, generates a jwt token, and shoves it in a cookie
	// This is the only path that can be taken for the external
	// There is sign in.
	// TODO: Signout
	ext.POST("/signout", signout())   // Lets invalidate the cookie

	//
	// Restricted group
	// This is an internal call made by all other microservices
	//
	v := internal.Group("/validate")
	// Configure middleware with the custom claims type
	config := middleware.JWTConfig{
		Claims:     &m.Claims{},
		SigningKey: []byte("my_secret_key"),
		TokenLookup: "cookie:jwt",
	}
	v.Use(validatetoken(db))                         // Lets validate the Token to make sure its  valid and user is still valid
	v.Use(middleware.JWTWithConfig(config))      // If we are good, lets unpack it
	v.GET("", GeneratePayload)                  // lets place the payload

	var wg sync.WaitGroup

	wg.Add(2)

	// Lets fire up the internal first
	go func() {
		if Properties.InternalMS.IsHTTPS {
			internal.Logger.Fatal(internal.StartTLS(fmt.Sprintf(":%d", Properties.InternalMS.Port), "./keys/server.crt","./keys/server.key"))
		} else {
			internal.Logger.Fatal(internal.Start(fmt.Sprintf(":%d", Properties.InternalMS.Port)))
		}
		wg.Done()
	}()

	// Lets fire up the external now
	go func() {
		if Properties.ExternalMS.IsHTTPS {
			ext.Logger.Fatal(ext.StartTLS(fmt.Sprintf(":%d", Properties.ExternalMS.Port), "./keys/server.crt","./keys/server.key"))
		} else {
			ext.Logger.Fatal(ext.Start(fmt.Sprintf(":%d", Properties.ExternalMS.Port)))
		}
		wg.Done()
	}()

	wg.Wait()
}


// Set up Logging
// Load up the config file and let it rip
func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	InitConfiguration("./")
}

//
// A very simple startup
//
func main() {

	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8%sparseTime=true", Properties.Db.User, Properties.Db.Pass, Properties.Db.Host, Properties.Db.Port, Properties.Db.Dbname, "&")
	db, err := gorm.Open(Properties.Db.Dialect, connectionString)
	if err != nil {
		log.Error(err.Error())
		log.Panic("failed to connect database")
	} else if db != nil {
		defer db.Close()
		log.Info("Connected to the database with the following String: %s", connectionString)
		db.SingularTable(true)
		handleRequests(db)
	}

}