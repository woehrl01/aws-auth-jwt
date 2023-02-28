package main

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

type Settings struct {
	logLevel                string
	policyFolder            string
	privateKeyFile          string
	publicKeyFile           string
	issuer                  string
	tokenExpirationDuration time.Duration
}

var settings Settings

func initSettings() {
	settings = Settings{
		logLevel:                "info",
		policyFolder:            "",
		privateKeyFile:          "",
		publicKeyFile:           "",
		issuer:                  "aws-auth-jwt",
		tokenExpirationDuration: 1 * time.Hour,
	}

	if os.Getenv("LOG_LEVEL") != "" {
		settings.logLevel = os.Getenv("LOG_LEVEL")
	}

	if os.Getenv("OPA_POLICY_FILE") != "" {
		settings.policyFolder = os.Getenv("OPA_POLICY_FILE")
	}

	if os.Getenv("OPA_POLICY_FOLDER") != "" {
		settings.policyFolder = os.Getenv("OPA_POLICY_FOLDER")
	}

	if os.Getenv("PRIVATE_KEY_FILE") != "" {
		settings.privateKeyFile = os.Getenv("PRIVATE_KEY_FILE")
	}

	if os.Getenv("PUBLIC_KEY_FILE") != "" {
		settings.publicKeyFile = os.Getenv("PUBLIC_KEY_FILE")
	}

	if os.Getenv("ISSUER") != "" {
		settings.issuer = os.Getenv("ISSUER")
	}

	if os.Getenv("TOKEN_EXPIRATION_DURATION") != "" {
		settings.tokenExpirationDuration, _ = time.ParseDuration(os.Getenv("TOKEN_EXPIRATION_DURATION"))
	} else if os.Getenv("TOKEN_EXPIRATION_HOURS") != "" {
		settings.tokenExpirationDuration, _ = time.ParseDuration(os.Getenv("TOKEN_EXPIRATION_HOURS") + "h")
	}

}

func (s *Settings) hasCustomPolicy() bool {
	return s.policyFolder != ""
}

func (s *Settings) hasCustomKeys() bool {
	return s.privateKeyFile != "" && s.publicKeyFile != ""
}

func (s *Settings) getLogLevel() log.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		return log.DebugLevel
	case "info":
		return log.InfoLevel
	case "warn":
		return log.WarnLevel
	case "error":
		return log.ErrorLevel
	case "fatal":
		return log.FatalLevel
	case "panic":
		return log.PanicLevel
	default:
		return log.InfoLevel
	}
}
