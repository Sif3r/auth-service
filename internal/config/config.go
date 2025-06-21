package config

import (
	"fmt"
	"os"
	"strings"
)

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	vars := map[string]*string{
		"PORT":             &cfg.Port,
		"DATABASE_URL":     &cfg.DatabaseURL,
		"REDIS_URL":        &cfg.RedisURL,
		"REDIS_PASSWORD":   &cfg.RedisPassword,
		"PRIVATE_KEY_PATH": &cfg.PrivateKeyPath,
		"PUBLIC_KEY_PATH":  &cfg.PublicKeyPath,
		"JWT_ISSUER":       &cfg.Issuer,
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
