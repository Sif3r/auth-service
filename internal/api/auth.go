package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/Sif3r/auth-service/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) LoginUser(c *gin.Context) {
	var req LoginUser
	var user repository.Auth
	var err error
	logger := getLogger(c)

	if err = c.ShouldBindJSON(&req); err != nil {
		handleError(
			c,
			newAPIError(http.StatusBadRequest, gin.H{"error": "Invalid request body"}, err),
		)
		return
	}

	if _, emailErr := mail.ParseAddress(req.Identifier); emailErr == nil {
		user, err = h.repo.GetUserByEmail(c.Request.Context(), req.Identifier)
	} else {
		user, err = h.repo.GetUserByUsername(c.Request.Context(), req.Identifier)
	}

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			handleError(
				c,
				newAPIError(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"}, err),
			)
		} else {
			handleError(c, newAPIError(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"}, err))
		}
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash.String), []byte(req.Password)); err != nil {
		handleError(
			c,
			newAPIError(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"}, err),
		)
		return
	}

	refreshToken, accessToken, err := h.tokenManager.GenerateTokens(user.ID.String())
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to generate tokens"},
				err,
			),
		)
		return
	}

	logger.Info(
		"User logged in successfully",
		slog.String("userID", user.ID.String()),
		slog.String("username", user.Username),
	)
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (h *Handler) Logout(c *gin.Context) {
	var req Logout
	if err := c.ShouldBindJSON(&req); err != nil {
		handleError(
			c,
			newAPIError(http.StatusBadRequest, gin.H{"error": "Invalid request body"}, err),
		)
		return
	}

	claims, err := h.tokenManager.ValidateRefreshToken(c, req.RefreshToken)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusUnauthorized,
				gin.H{"error": "Invalid or expired refresh token"},
				err,
			),
		)
		return
	}

	err = h.tokenManager.BlacklistJTI(c.Request.Context(), claims.ID, claims.ExpiresAt.Time.Unix())
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to blacklist token"},
				err,
			),
		)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (h *Handler) RefreshToken(c *gin.Context) {
	var req RefreshToken
	if err := c.ShouldBindJSON(&req); err != nil {
		handleError(
			c,
			newAPIError(http.StatusBadRequest, gin.H{"error": "Invalid request body"}, err),
		)
		return
	}

	claims, err := h.tokenManager.ValidateRefreshToken(c, req.RefreshToken)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusUnauthorized,
				gin.H{"error": "Invalid or expired refresh token"},
				err,
			),
		)
		return
	}

	parsedUserID, err := uuid.Parse(claims.UserID)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Internal server error: invalid user ID in token"},
				err,
			),
		)
		return
	}

	pgUserID := pgtype.UUID{Bytes: parsedUserID, Valid: true}
	_, err = h.repo.GetUserByID(c.Request.Context(), pgUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			handleError(
				c,
				newAPIError(
					http.StatusUnauthorized,
					gin.H{"error": "User not found, refresh token invalidated"},
					err,
				),
			)
		} else {
			handleError(c, newAPIError(http.StatusInternalServerError, gin.H{"error": "Failed to validate user for refresh"}, err))
		}
		return
	}

	newRefreshToken, newAccessToken, err := h.tokenManager.GenerateTokens(claims.UserID)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to generate new tokens"},
				err,
			),
		)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

func (h *Handler) GetPublicKey(c *gin.Context) {
	logger := getLogger(c)
	pubKey := h.tokenManager.GetPublicToken()
	if pubKey == nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Public key not found in token manager"},
				errors.New("public key is nil"),
			),
		)
		return
	}

	j, err := jwk.Import(pubKey)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to convert public key to JWK"},
				err,
			),
		)
		return
	}

	if err = j.Set(jwk.KeyIDKey, "auth-service-key"); err != nil {
		logger.Warn("Failed to set JWK KeyID", "error", err)
	}
	if err = j.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		logger.Warn("Failed to set JWK Algorithm", "error", err)
	}
	if err = j.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		logger.Warn("Failed to set JWK KeyUsage", "error", err)
	}

	keySet := jwk.NewSet()
	if err = keySet.AddKey(j); err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to add public key to JWK Set"},
				err,
			),
		)
		return
	}

	c.JSON(http.StatusOK, keySet)
}
