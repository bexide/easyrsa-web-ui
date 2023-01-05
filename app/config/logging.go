package config

import "github.com/spf13/viper"

type LoggingConfig struct {
	Level string
}

func newLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level: viper.GetString(`logging.level`),
	}
}
