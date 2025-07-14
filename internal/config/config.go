package config

import (
	"fmt"
	"os"
	"strings"
)

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	vars := map[string]*string{
		"PORT":                 &cfg.Port,
		"DATABASE_URL":         &cfg.DatabaseURL,
		"REDIS_URL":            &cfg.RedisURL,
		"REDIS_PASSWORD":       &cfg.RedisPassword,
		"PRIVATE_KEY_PATH":     &cfg.PrivateKeyPath,
		"PUBLIC_KEY_PATH":      &cfg.PublicKeyPath,
		"JWT_ISSUER":           &cfg.Issuer,
		"GIN_MODE":             &cfg.GinMode,
		"GOOGLE_CLIENT_ID":     &cfg.GoogleClientID,
		"GOOGLE_CLIENT_SECRET": &cfg.GoogleClientSecret,
		"GITHUB_CLIENT_ID":     &cfg.GithubClientID,
		"GITHUB_CLIENT_SECRET": &cfg.GithubClientSecret,
		"CALLBACK_URL":         &cfg.CallbackURL,
		"SESSION_SECRET":       &cfg.SessionSecret,
	}

	for key, valPtr := range vars {
		*valPtr = os.Getenv(key)
		if *valPtr == "" {
			return nil, fmt.Errorf("error: %s environment variable not set", key)
		}
	}

	audienceStr := os.Getenv("JWT_AUDIENCE")
	if audienceStr != "" {
		cfg.Audience = strings.Split(audienceStr, ",")
		for i, aud := range cfg.Audience {
			cfg.Audience[i] = strings.TrimSpace(aud)
		}
	} else {
		cfg.Audience = []string{}
	}
	return cfg, nil
}
