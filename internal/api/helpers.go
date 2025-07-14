package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Sif3r/auth-service/internal/middleware"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func getLogger(c *gin.Context) *slog.Logger {
	loggerVal, exists := c.Get(string(middleware.LoggerKey))
	if !exists {
		return slog.Default()
	}
	logger, ok := loggerVal.(*slog.Logger)
	if !ok {
		return slog.Default()
	}
	return logger
}

func (h *Handler) getUserIDFromContext(c *gin.Context) (pgtype.UUID, error) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		err := errors.New("user ID not found in context")
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Internal server error: user ID not found in context"},
				err,
			),
		)
		return pgtype.UUID{}, err
	}

	userIDStr, ok := userIDVal.(string)
	if !ok {
		err := errors.New("invalid user ID type in context")
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Internal server error: invalid user ID type"},
				err,
			),
		)
		return pgtype.UUID{}, err
	}

	parsedUserID, err := uuid.Parse(userIDStr)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Internal server error: invalid user ID format"},
				err,
			),
		)
		return pgtype.UUID{}, err
	}

	return pgtype.UUID{
		Bytes: parsedUserID,
		Valid: true,
	}, nil
}
