package token

import (
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type RedisClientInterface interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(
		ctx context.Context,
		key string,
		value interface{},
		expiration time.Duration,
	) *redis.StatusCmd
	Ping(ctx context.Context) *redis.StatusCmd
}

type Claims struct {
	UserID   string   `json:"sub"`
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	Type     string   `json:"type"`
	jwt.RegisteredClaims
}

type Manager struct {
	RedisClient RedisClientInterface
	PrivateKey  *ecdsa.PrivateKey
	PublicKey   *ecdsa.PublicKey
	Issuer      string
	Audience    []string
}
