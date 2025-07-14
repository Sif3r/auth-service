package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/Sif3r/auth-service/internal/middleware"
	"github.com/Sif3r/auth-service/internal/repository"
	"github.com/Sif3r/auth-service/internal/token"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/crypto/bcrypt"
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

func NewAPIHandler(repo *repository.Queries, tm *token.Manager, logger *slog.Logger) *Handler {
	return &Handler{
		repo:         repo,
		tokenManager: tm,
		Logger:       logger,
	}
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

func (h *Handler) CreateUser(c *gin.Context) {
	var req CreateUser
	logger := getLogger(c)

	if err := c.ShouldBindJSON(&req); err != nil {
		handleError(
			c,
			newAPIError(http.StatusBadRequest, gin.H{"error": "Invalid request body"}, err),
		)
		return
	}

	passwordHashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Could not process request"},
				err,
			),
		)
		return
	}

	arg := repository.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: pgtype.Text{String: string(passwordHashed), Valid: true},
	}

	_, err = h.repo.CreateUser(c.Request.Context(), arg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			handleError(
				c,
				newAPIError(
					http.StatusConflict,
					gin.H{"error": "Username or email already exists"},
					err,
				),
			)
		} else {
			handleError(c, newAPIError(http.StatusInternalServerError, gin.H{"error": "Failed to create user"}, err))
		}
		return
	}

	logger.Info(
		"User created successfully",
		slog.String("username", req.Username),
		slog.String("email", req.Email),
	)
	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

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

func (h *Handler) DeleteUser(c *gin.Context) {
	pgUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return
	}

	err = h.repo.DeleteUser(c.Request.Context(), pgUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			handleError(c, newAPIError(http.StatusNotFound, gin.H{"error": "User not found"}, err))
		} else {
			handleError(c, newAPIError(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"}, err))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func (h *Handler) GetUserInfo(c *gin.Context) {
	pgUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return
	}

	user, err := h.repo.GetUserByID(c.Request.Context(), pgUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			handleError(c, newAPIError(http.StatusNotFound, gin.H{"error": "User not found"}, err))
		} else {
			handleError(c, newAPIError(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"}, err))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":           user.ID.String(),
		"username":     user.Username,
		"email":        user.Email,
		"created_at":   user.CreatedAt.Time,
		"last_updated": user.LastUpdated.Time,
	})
}

func (h *Handler) UpdateUserInfo(c *gin.Context) {
	pgUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return
	}

	_, err = h.repo.GetUserByID(c.Request.Context(), pgUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			handleError(c, newAPIError(http.StatusNotFound, gin.H{"error": "User not found"}, err))
		} else {
			handleError(c, newAPIError(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user for update"}, err))
		}
		return
	}

	var req UpdateUser
	if err = c.ShouldBindJSON(&req); err != nil {
		handleError(
			c,
			newAPIError(http.StatusBadRequest, gin.H{"error": "Invalid request body"}, err),
		)
		return
	}

	if req.Username == "" && req.Email == "" {
		handleError(
			c,
			newAPIError(http.StatusBadRequest, gin.H{"error": "No update fields provided"}, nil),
		)
		return
	}

	if req.Username != "" {
		err = h.repo.UpdateUserUsername(
			c.Request.Context(),
			repository.UpdateUserUsernameParams{ID: pgUserID, Username: req.Username},
		)
		if err != nil {
			handleError(
				c,
				newAPIError(
					http.StatusInternalServerError,
					gin.H{"error": "Failed to update username"},
					err,
				),
			)
			return
		}
	}

	if req.Email != "" {
		err = h.repo.UpdateUserEmail(
			c.Request.Context(),
			repository.UpdateUserEmailParams{ID: pgUserID, Email: req.Email},
		)
		if err != nil {
			handleError(
				c,
				newAPIError(
					http.StatusInternalServerError,
					gin.H{"error": "Failed to update email"},
					err,
				),
			)
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "User information updated successfully"})
}

func (h *Handler) ChangePassword(c *gin.Context) {
	pgUserID, err := h.getUserIDFromContext(c)
	if err != nil {
		return
	}

	var req ChangePassword
	if err = c.ShouldBindJSON(&req); err != nil {
		handleError(
			c,
			newAPIError(http.StatusBadRequest, gin.H{"error": "Invalid request body"}, err),
		)
		return
	}

	user, err := h.repo.GetUserByID(c.Request.Context(), pgUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			handleError(
				c,
				newAPIError(http.StatusUnauthorized, gin.H{"error": "User not found"}, err),
			)
		} else {
			handleError(c, newAPIError(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user for password change"}, err))
		}
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash.String), []byte(req.CurrentPassword)); err != nil {
		handleError(
			c,
			newAPIError(http.StatusUnauthorized, gin.H{"error": "Invalid current password"}, err),
		)
		return
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to hash new password"},
				err,
			),
		)
		return
	}

	err = h.repo.UpdateUserPassword(
		c.Request.Context(),
		repository.UpdateUserPasswordParams{
			ID:           pgUserID,
			PasswordHash: pgtype.Text{String: string(newPasswordHash), Valid: true},
		},
	)
	if err != nil {
		handleError(
			c,
			newAPIError(
				http.StatusInternalServerError,
				gin.H{"error": "Failed to update password"},
				err,
			),
		)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}
