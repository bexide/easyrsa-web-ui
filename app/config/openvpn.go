package config

import "github.com/spf13/viper"

type OpenvpnConfig struct {
	Support      bool
	ClientConfig string
}

func newOpenvpnConfig() OpenvpnConfig {
	return OpenvpnConfig{
		Support:      viper.GetBool(`openvpn.support`),
		ClientConfig: viper.GetString(`openvpn.client_config`),
	}
}
