package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

func Logging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		latency := time.Since(start)

		loggerVal, exists := c.Get(string(LoggerKey))
		if !exists {
			return
		}

		requestLogger, ok := loggerVal.(*slog.Logger)
		if !ok {
			return
		}

		requestLogger.Info("Request handled",
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("latency", latency),
			slog.String("client_ip", c.ClientIP()),
		)
	}
}
