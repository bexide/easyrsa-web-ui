package config

import "github.com/spf13/viper"

type OpenvpnConfig struct {
	Support    bool
	ServerName string
	ServerPort string
}

func newOpenvpnConfig() OpenvpnConfig {
	return OpenvpnConfig{
		Support:    viper.GetBool(`openvpn.support`),
		ServerName: viper.GetString(`openvpn.server`),
		ServerPort: viper.GetString(`openvpn.port`),
	}
}
