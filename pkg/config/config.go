package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	LogLevel         string
	ListenAddr       string
	BouncerApiKey    string
	BouncerHost      string
	BouncerScheme    string
	BanResponseCode  int
	BanResponseMsg   string
	ClientIPHeader   string
	CountryHeader    string
	AllowedCountries string
	RateLimit        int
	BucketSize       int
	RedisAddresses   []string
	RedisPassword    string
	RedisMaster      string
}

const envPreffix = "CROWDSEC_BOUNCER_"

func NewConfig() *Config {
	redisAddr := make([]string, 0)
	for _, envVar := range os.Environ() {
		if strings.Contains(envVar, envPreffix+"REDIS_ADDRESS_") {
			_, addr, f := strings.Cut(envVar, "=")
			if f {
				redisAddr = append(redisAddr, addr)
			}
		}
	}
	return &Config{
		LogLevel:         optionalEnv(envPreffix+"LOG_LEVEL", ""),
		ListenAddr:       optionalEnv(envPreffix+"LISTEN_ADDRESS", ":8080"),
		BouncerApiKey:    requiredEnv(envPreffix + "API_KEY"),
		BouncerHost:      requiredEnv(envPreffix + "AGENT_HOST"),
		BouncerScheme:    optionalEnv(envPreffix+"SCHEME", "http"),
		BanResponseCode:  expectedResponseCode(envPreffix + "BAN_RESPONSE_CODE"),
		BanResponseMsg:   optionalEnv(envPreffix+"BAN_RESPONSE_MSG", "Forbidden"),
		ClientIPHeader:   optionalEnv(envPreffix+"CLIENT_IP_HEADER", "X-Real-Ip"),
		CountryHeader:    optionalEnv(envPreffix+"COUNTRY_HEADER", ""),
		AllowedCountries: optionalEnv(envPreffix+"ALLOWED_COUNTRIES", ""),
		RateLimit:        optionalEnvInt(envPreffix+"RATE_LIMIT", 5),
		BucketSize:       optionalEnvInt(envPreffix+"BUCKET_SIZE", 15),
		RedisPassword:    optionalEnv(envPreffix+"REDIS_PASSWORD", ""),
		RedisAddresses:   redisAddr,
		RedisMaster:      optionalEnv(envPreffix+"REDIS_MASTER", "mymaster"),
	}
}

func optionalEnv(varName string, optional string) string {
	envVar := os.Getenv(varName)
	if envVar == "" {
		return optional
	}
	return envVar
}

func optionalEnvInt(varName string, optional int) int {
	envVar := os.Getenv(varName)
	if envVar == "" {
		return optional
	}
	val, err := strconv.Atoi(envVar)
	if err != nil {
		log.Fatalf("The env var %s could not be converted to number. Exiting", varName)
	}
	return val
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
