package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/Sif3r/auth-service/internal/token"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(tm *token.Manager, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			c.Abort()
			return
		}

		accessToken := parts[1]
		claims, err := tm.ValidateAccessToken(accessToken)
		if err != nil {
			logger.Warn("Access token validation failed", "error", err)
			c.JSON(
				http.StatusUnauthorized,
				gin.H{"error": "Invalid or expired access token", "details": err.Error()},
			)
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}
