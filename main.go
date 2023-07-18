package main

import (
	"easyrsa-web-ui/app/config"
	"easyrsa-web-ui/app/easyrsa"
	"easyrsa-web-ui/web"
	"fmt"
	"os"

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

	if len(os.Args) > 1 {
		if os.Args[1] == "init" {
			if !easyrsa.IsInitialized() {
				easyrsa.Initialize()
				fmt.Print("pki initialize")
			}
			return
		}
		if os.Args[1] == "gen-crl" {
			easyrsa.GenCrl()
			fmt.Print("pki gen-crl")
			return
		}
	}

	web.Init()
}
