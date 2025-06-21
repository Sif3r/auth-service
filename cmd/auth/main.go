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
	"github.com/Sif3r/auth-service/internal/repository"
	"github.com/Sif3r/auth-service/internal/token"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

const (
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 30 * time.Second
	readHeaderTimeout = 20 * time.Second
	shutdownTimeout   = 5 * time.Second
)

func run(logger *slog.Logger) error {
	ctx := context.Background()

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		return err
	}

	conn, err := pgx.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %w", err)
	}
	defer func() {
		if cerr := conn.Close(context.Background()); cerr != nil {
			logger.Error("Failed to close database connection", "error", cerr)
		}
	}()

	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisURL,
		Password: cfg.RedisPassword,
	})

	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("could not connect to Redis: %w", err)
	}

	queries := repository.New(conn)
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
