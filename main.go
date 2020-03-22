package main

import (
	"fmt"
	cfg "generic-as/config"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"os"
	repo "scaha_micro_member/repository"
)

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*Claims)
	name := claims.UserName
	return c.String(http.StatusOK, "Welcome "+name+"!")
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

//
// Lets handle these bad boys
//
func handleRequest(dbgorm *gorm.DB) {

	e := echo.New()
	db := repo.DAO{dbgorm}

	// Cache certificates
	e.AutoTLSManager.Cache = autocert.DirCache("./.cache")
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	// "Signin" and "Welcome" are the handlers that we will implement
	e.POST("/signin", Signin(db))
	e.GET("/validate", Validate(db))
	e.POST("/refresh", Refresh(db))
	e.GET("/", func(c echo.Context) error {
		return c.HTML(http.StatusOK, `
			<h1>Welcome to Echo!</h1>
			<h3>TLS certificates automatically installed from Let's Encrypt :)</h3>
		`)
	})


	// Restricted group
	r := e.Group("/restricted")

	// Configure middleware with the custom claims type
	config := middleware.JWTConfig{
		Claims:     &Claims{},
		SigningKey: []byte("my_secret_key"),
		TokenLookup: "cookie:jwt",
	}
	r.Use(middleware.JWTWithConfig(config))
	r.Use(RefreshToken)
	r.GET("", restricted)
	// start the server on port 4050
	e.Logger.Fatal(e.StartTLS(":4050", "./server.crt","./server.key"))
}

func initLogging() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {

	initLogging()
	cfg.InitConfiguration("./")
	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8%sparseTime=true", cfg.Properties.Db.User, cfg.Properties.Db.Pass, cfg.Properties.Db.Host, cfg.Properties.Db.Port, cfg.Properties.Db.Dbname, "&")
	log.Info(connectionString)

	db, err := gorm.Open("mysql", connectionString)

	if err != nil {
		log.Error(err.Error())
		log.Panic("failed to connect database")
	}
	log.Info("Connected to the database with the following String: %s", connectionString)
	db.SingularTable(true)
	defer db.Close()

	handleRequest(db)
}
