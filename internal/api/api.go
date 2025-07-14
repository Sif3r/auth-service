package api

import (
	"log/slog"

	"github.com/Sif3r/auth-service/internal/repository"
	"github.com/Sif3r/auth-service/internal/token"
)

func NewAPIHandler(repo *repository.Queries, tm *token.Manager, logger *slog.Logger) *Handler {
	return &Handler{
		repo:         repo,
		tokenManager: tm,
		Logger:       logger,
	}
}
