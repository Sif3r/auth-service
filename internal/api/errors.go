package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal server error occurred"})
	}
}
