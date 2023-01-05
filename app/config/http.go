package config

import "github.com/spf13/viper"

type HttpConfig struct {
	ListenHost string
	ListenPort string
}

func newHttpConfig() HttpConfig {
	return HttpConfig{
		ListenHost: viper.GetString(`http.host`),
		ListenPort: viper.GetString(`http.port`),
	}
}
