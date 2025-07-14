package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	ErrInvalidRequestBody = "Invalid request body"
	ErrInvalidCredentials = "Invalid credentials" // #nosec G101
	ErrUserNotFound       = "User not found"
	ErrInternalServer     = "An internal server error occurred"
)

type apiError struct {
	code        int
	message     gin.H
	internalErr error
}

func (e *apiError) Error() string {
	if e.internalErr != nil {
		return e.internalErr.Error()
	}
	return "API error"
}

func newAPIError(code int, message gin.H, internalErr error) *apiError {
	return &apiError{
		code:        code,
		message:     message,
		internalErr: internalErr,
	}
}

func newInvalidRequestBodyError(err error) *apiError {
	return newAPIError(http.StatusBadRequest, gin.H{"error": ErrInvalidRequestBody}, err)
}

func newInvalidCredentialsError(err error) *apiError {
	return newAPIError(http.StatusUnauthorized, gin.H{"error": ErrInvalidCredentials}, err)
}

func newUserNotFoundError(err error) *apiError {
	return newAPIError(http.StatusNotFound, gin.H{"error": ErrUserNotFound}, err)
}

func newInternalServerError(message string, err error) *apiError {
	return newAPIError(http.StatusInternalServerError, gin.H{"error": message}, err)
}

func handleError(c *gin.Context, err error) {
	logger := getLogger(c)

	var apiErr *apiError
	if errors.As(err, &apiErr) {
		if apiErr.internalErr != nil {
			logger.Warn("API error handled", "status", apiErr.code, "error", apiErr.internalErr)
		}
		c.JSON(apiErr.code, apiErr.message)
	} else {
		logger.Error("Unhandled internal error", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrInternalServer})
	}
}
