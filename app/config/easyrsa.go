package config

import "github.com/spf13/viper"

type EasyrsaConfig struct {
	Path    string
	PkiPath string
	Package string
}

func newEasyrsaConfig() EasyrsaConfig {
	viper.SetDefault("easyrsa.pth", "./easyrsa")
	viper.SetDefault("easyrsa.pki_path", "./easyrsa/pki")
	viper.SetDefault("easyrsa.package", "https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.1/EasyRSA-3.2.1.tgz")
	return EasyrsaConfig{
		Path:    viper.GetString(`easyrsa.path`),
		PkiPath: viper.GetString(`easyrsa.pki_path`),
		Package: viper.GetString(`easyrsa.package`),
	}
}
