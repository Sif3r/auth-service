package api

import (
	"log/slog"

	"github.com/Sif3r/auth-service/internal/repository"
	"github.com/Sif3r/auth-service/internal/token"
)

type Handler struct {
	repo         *repository.Queries
	tokenManager *token.Manager
	Logger       *slog.Logger
}

type CreateUser struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginUser struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password"   binding:"required"`
}

type RefreshToken struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type Logout struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type UpdateUser struct {
	Username string `json:"username"`
	Email    string `json:"email"    binding:"omitempty,email"`
}

type ChangePassword struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password"     binding:"required"`
}
