package config

type Config struct {
	Port               string
	DatabaseURL        string
	RedisURL           string
	RedisPassword      string
	PrivateKeyPath     string
	PublicKeyPath      string
	Issuer             string
	Audience           []string
	GinMode            string
	GoogleClientID     string
	GoogleClientSecret string
	GithubClientID     string
	GithubClientSecret string
	CallbackURL        string
	SessionSecret      string
}
