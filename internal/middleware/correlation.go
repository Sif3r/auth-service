package middleware

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ContextKey string

const (
	CorrelationIDKey ContextKey = "correlationID"
	LoggerKey        ContextKey = "logger"
)

func CorrelationID(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationID := c.GetHeader("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}
		c.Header("X-Correlation-ID", correlationID)
		requestLogger := logger.With(slog.String(string(CorrelationIDKey), correlationID))
		c.Set(string(LoggerKey), requestLogger)
		c.Next()
	}
}
