package api

import (
	"net/http"

	"github.com/Sif3r/auth-service/internal/middleware"
	"github.com/gin-gonic/gin"
)

func SetupRouter(handler *Handler) *gin.Engine {
	router := gin.Default()

	router.Use(middleware.CorrelationID(handler.Logger))
	router.Use(middleware.Logging())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP"})
	})
	router.GET("/.well-known/jwks.json", handler.GetPublicKey)
	v1 := router.Group("/v1")
	{
		v1.POST("/register", handler.CreateUser)
		v1.POST("/login", handler.LoginUser)
		v1.POST("/refresh-token", handler.RefreshToken)
		v1.POST("/logout", handler.Logout)

		authenticated := v1.Group("/me")
		authenticated.Use(middleware.AuthMiddleware(handler.tokenManager, handler.Logger))
		{
			authenticated.DELETE("", handler.DeleteUser)
			authenticated.GET("", handler.GetUserInfo)
			authenticated.PUT("", handler.UpdateUserInfo)
			authenticated.POST("/change-password", handler.ChangePassword)
		}
	}
	return router
}
