package config

import "github.com/spf13/viper"

type EasyrsaConfig struct {
	Path string
}

func newEasyrsaConfig() EasyrsaConfig {
	return EasyrsaConfig{
		Path: viper.GetString(`easyrsa.path`),
	}
}
