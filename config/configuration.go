package config

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"path/filepath"
)

/*
 General Config information  about the overall system
*/
type SystemConfig struct {
	HeartBeatSEC       int    `mapstructure:"heartbeatsec"`      // How frequent to do we report out systems
	IsProfilerEnabled  bool   `mapstructure:"isProfilerEnabled"` // Is them memory profiler enabled
	ProfilerPort       string `mapstructure:"ProfilerPort"`      // what port is the memory profiler enabled on
	ReclaimMemory      bool   `mapstructure:"reclaimMemory"`
	ProductSearchLimit int    `mapstructure:"productSearchLimit"`
	ReloadConfig       chan int
}

/**
  DATABASE Configuration
  Pretty Straight Foward
*/
type DatabaseConfig struct {
	Dialect      string   `mapstructure: dialect`       // The dialect we need to be talking in for db information
	Host         string   `mapstructure:"host"`         // Host name
	Port         int      `mapstructure:"port"`         // What port are we connecting on?
	User         string   `mapstructure:"user"`         // user
	Pass         string   `mapstructure:"password"`     // password (should not be here)
	Dbname       string   `mapstructure:"dbname"`       // what database are we lookin at
	SSLMode      string   `mapstructure:"sslMode"`      // are we in sslMode?
	Poolsize     int      `mapstructure:"poolsize"`     // How big are we gonna let our datapool get
	HeartBeatSEC int      `mapstructure:"heartbeatsec"` // What is the reportout frequency
	IsEnabled    bool     `mapstructure:"isEnabled"`    // Is this service enabled?
	DsnParms     string    `mapstructure:"dsnParms"`    // Extra parameters passed on connect string
	ReloadConfig chan int  // we always want a way to singal a reload
}

/*
  This is the general configuration information for a
  microservice
*/
type MicroServiceConfig struct {
	Port             int  `mapstructure:"port"`
	IsHTTPS          bool `mapstructure:"isHTTPS"`
	IsCompressed     bool `mapstructure:"isCompressed"`
	IsEnabled        bool `mapstructure:"isEnabled"`
	RequestTimeoutMs int  `mapstructure:"requestTimeOutMs"`
}

/*
  This is the master properties structure that will have all the things we need to drive the program

*/
type config struct {
	System        SystemConfig        `mapstructure:"system"`
	Db            DatabaseConfig      `mapstructure:"database"`
	CcaeMS		  MicroServiceConfig  `mapstructure:"ccaeMicroService"`
	ReloadConfig  chan int
}

var Properties config // The real deal in holding the configuration(s)
var Path string       // Holds the path of where its located

//
// Lets init everything and do it as soon as this guy is referenced.

func ReloadConfiguration() {

	err := viper.ReadInConfig()

	if err != nil {
		log.Error("Config file not found...")
	}

	err = viper.Unmarshal(&Properties)
	if err != nil {
		log.Error(errors.Wrap(err, "unmarshal config file"))
	}

	//
	// Lets fire of reloading notice
	//
	Properties.System.ReloadConfig <- 1
	Properties.Db.ReloadConfig <- 1
}

func InitConfiguration(path string) {

	viper.SetConfigName("config")
	viper.SetConfigType("yml")
	viper.AddConfigPath(filepath.Dir(path))
	err := viper.ReadInConfig()

	if err != nil {
		log.Error("Config file not found...")
	}

	err = viper.Unmarshal(&Properties)
	if err != nil {
		log.Error(errors.Wrap(err, "unmarshal config file"))
	}

	//
	// Give them all a buffer here
	Properties.ReloadConfig = make(chan int, 1)
	Properties.System.ReloadConfig = make(chan int, 1)
	Properties.Db.ReloadConfig = make(chan int, 1)

}