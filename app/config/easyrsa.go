package config

import "github.com/spf13/viper"

type EasyrsaConfig struct {
	Path    string
	PkiPath string
}

func newEasyrsaConfig() EasyrsaConfig {
	viper.SetDefault("easyrsa.pth", "./easyrsa")
	viper.SetDefault("easyrsa.pki_path", "./easyrsa/pki")
	return EasyrsaConfig{
		Path:    viper.GetString(`easyrsa.path`),
		PkiPath: viper.GetString(`easyrsa.pki_path`),
	}
}
