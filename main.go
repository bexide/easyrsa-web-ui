package main

import (
	"easyrsa-web-ui/app/config"
	"easyrsa-web-ui/web"

	"github.com/sirupsen/logrus"
)

func main() {
	switch config.Current.Level {
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	}
	web.Init()
}
