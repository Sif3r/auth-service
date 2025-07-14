package api

import (
	"context"
	"net/http"

	"github.com/Sif3r/auth-service/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
)

func (h *Handler) BeginAuth(c *gin.Context) {
	provider := c.Param("provider")
	//nolint:revive,staticcheck // goth library requires the provider name to be in the context as a string.
	ctx := context.WithValue(c.Request.Context(), "provider", provider)
	req := c.Request.WithContext(ctx)

	gothic.BeginAuthHandler(c.Writer, req)
}

func (h *Handler) AuthCallback(c *gin.Context) {
	providerName := c.Param("provider")
	//nolint:revive,staticcheck // goth library requires the provider name to be in the context as a string.
	ctx := context.WithValue(c.Request.Context(), "provider", providerName)
	req := c.Request.WithContext(ctx)

	gothUser, err := gothic.CompleteUserAuth(c.Writer, req)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "failed to complete auth"},
				err,
			),
		)
		return
	}

	user, err := h.repo.GetUserByEmail(c.Request.Context(), gothUser.Email)
	if err != nil {
		arg := repository.CreateUserParams{
			Username: gothUser.NickName,
			Email:    gothUser.Email,
		}

		createdUser, createErr := h.repo.CreateUser(c.Request.Context(), arg)
		if createErr != nil {
			handleError(
				c,
				newAPIError(
					http.StatusInternalServerError,
					gin.H{"error": "failed to create user"},
					createErr,
				),
			)
			return
		}
		user.ID = createdUser.ID
	}

	refreshToken, accessToken, err := h.tokenManager.GenerateTokens(user.ID.String())
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "failed to generate tokens"},
				err,
			),
		)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
