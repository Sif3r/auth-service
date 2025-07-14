package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sif3r/auth-service/internal/api"
	"github.com/Sif3r/auth-service/internal/config"
	"github.com/Sif3r/auth-service/internal/oauth"
	"github.com/Sif3r/auth-service/internal/repository"
	"github.com/Sif3r/auth-service/internal/token"
	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/markbates/goth/gothic"
	"github.com/redis/go-redis/v9"
)

const (
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 30 * time.Second
	readHeaderTimeout = 20 * time.Second
	shutdownTimeout   = 5 * time.Second
)

func initOAuth(cfg *config.Config) {
	dayInSecond := 86400
	days := 30

	store := sessions.NewCookieStore([]byte(cfg.SessionSecret))
	store.MaxAge(days * dayInSecond)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	if cfg.GinMode == "release" {
		store.Options.Secure = true
	} else {
		store.Options.Secure = false
	}
	//nolint:reassign // gothic.Store is a global variable that must be configured.
	gothic.Store = store

	oauth.InitProviders(cfg)
}

func run(logger *slog.Logger) error {
	ctx := context.Background()

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		return err
	}

	initOAuth(cfg)

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("unable to create connection pool: %w", err)
	}
	defer pool.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisURL,
		Password: cfg.RedisPassword,
	})

	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("could not connect to Redis: %w", err)
	}

	queries := repository.New(pool)
	tm, err := token.NewTokenManager(*cfg, redisClient)
	if err != nil {
		return fmt.Errorf("failed to create token manager: %w", err)
	}

	apiHandler := api.NewAPIHandler(queries, tm, logger)
	r := api.SetupRouter(apiHandler)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	serverErrors := make(chan error, 1)

	go func() {
		logger.Info("Starting server", "port", cfg.Port)
		serverErrors <- srv.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case serverErr := <-serverErrors:
		if !errors.Is(serverErr, http.ErrServerClosed) {
			return fmt.Errorf("failed to run server: %w", serverErr)
		}
	case sig := <-shutdown:
		logger.Info("Shutdown signal received", "signal", sig)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.Error("Graceful shutdown failed", "error", shutdownErr)
			if closeErr := srv.Close(); closeErr != nil {
				logger.Error("Failed to force close server", "error", closeErr)
			}
		}

		logger.Info("Server shut down gracefully")
	}

	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("Application failed", "error", err)
		os.Exit(1)
	}
}
