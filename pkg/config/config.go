package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	BouncerApiKey   string
	BouncerHost     string
	BouncerScheme   string
	BanResponseCode int
	BanResponseMsg  string
	ClientIPHeader  string
}

func NewConfig() *Config {
	return &Config{
		BouncerApiKey:   requiredEnv("CROWDSEC_BOUNCER_API_KEY"),
		BouncerHost:     requiredEnv("CROWDSEC_AGENT_HOST"),
		BouncerScheme:   optionalEnv("CROWDSEC_BOUNCER_SCHEME", "http"),
		BanResponseCode: expectedResponseCode("CROWDSEC_BOUNCER_BAN_RESPONSE_CODE"),
		BanResponseMsg:  optionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_MSG", "Forbidden"),
		ClientIPHeader:  optionalEnv("CROWDSEC_BOUNCER_CLIENT_IP_HEADER", "X-Real-Ip"),
	}
}

func optionalEnv(varName string, optional string) string {
	envVar := os.Getenv(varName)
	if envVar == "" {
		return optional
	}
	return envVar
}

func requiredEnv(varName string) string {
	envVar := os.Getenv(varName)
	if envVar == "" {
		log.Fatalf("The required env var %s is not provided. Exiting", varName)
	}
	return envVar
}

func expectedResponseCode(varName string) int {
	banResponseCode := optionalEnv(varName, "403")
	parsedCode, err := strconv.Atoi(banResponseCode)
	if err != nil {
		log.Fatalf("The value for env var %s is not an int. It should be a valid http response code.", banResponseCode)
	}
	if parsedCode < 100 || parsedCode > 599 {
		log.Fatalf("The value for env var %s should be a valid http response code between 100 and 599 included.", banResponseCode)
	}
	return parsedCode
}
