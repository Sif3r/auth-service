package oauth

import (
	"github.com/Sif3r/auth-service/internal/config"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

func InitProviders(cfg *config.Config) {
	goth.UseProviders(
		google.New(
			cfg.GoogleClientID,
			cfg.GoogleClientSecret,
			cfg.CallbackURL+"/v1/google/callback",
			"email",
			"profile",
		),
		github.New(
			cfg.GithubClientID,
			cfg.GithubClientSecret,
			cfg.CallbackURL+"/v1/github/callback",
			"user:email",
		),
	)
}
