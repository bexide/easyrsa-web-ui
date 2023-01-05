package config

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/viper"
)

type Config struct {
	EasyrsaConfig
	LoggingConfig
	HttpConfig
	OpenvpnConfig
}

var Current *Config

func init() {
	_, err := os.Stat("./config.toml")
	if err == nil {
		Current = newConfig("./config.toml")
		return
	}
	_, b, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(b), "../..")
	Current = newConfig(root + "/config.toml")
}

func newConfig(filepath string) *Config {
	c := Config{}
	viper.SetConfigFile(filepath)
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
	c.EasyrsaConfig = newEasyrsaConfig()
	c.LoggingConfig = newLoggingConfig()
	c.HttpConfig = newHttpConfig()
	c.OpenvpnConfig = newOpenvpnConfig()
	return &c
}
