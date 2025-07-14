package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Sif3r/auth-service/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

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
