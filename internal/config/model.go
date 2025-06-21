package config

type Config struct {
	Port           string
	DatabaseURL    string
	RedisURL       string
	RedisPassword  string
	PrivateKeyPath string
	PublicKeyPath  string
	Issuer         string
	Audience       []string
}
