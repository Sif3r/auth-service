package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Sif3r/auth-service/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	refreshTokenDuration = 7 * 24 * time.Hour // 7 days
	accessTokenDuration  = 15 * time.Minute   // 15 minutes
)

func LoadAndParsePrivateKey(privateKeyPath string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, errors.New("failed to decode PEM block from private key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an ECDSA private key")
	}
	return ecdsaPrivateKey, nil
}

func LoadAndParsePublicKey(publicKeyPath string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	if publicKeyBlock == nil {
		return nil, errors.New("failed to decode PEM block from public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an ECDSA public key")
	}
	return ecdsaPublicKey, nil
}

func NewTokenManager(cfg config.Config, redisClient RedisClientInterface) (*Manager, error) {
	ecdsaPrivateKey, err := LoadAndParsePrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	ecdsaPublicKey, err := LoadAndParsePublicKey(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}
	return &Manager{
		PrivateKey:  ecdsaPrivateKey,
		PublicKey:   ecdsaPublicKey,
		Issuer:      cfg.Issuer,
		Audience:    cfg.Audience,
		RedisClient: redisClient,
	}, nil
}

func (tm *Manager) GenerateRefreshToken(userID string) (string, error) {
	now := time.Now()
	jti := uuid.New().String()

	refreshTokenClaims := &Claims{
		UserID:   userID,
		Issuer:   tm.Issuer,
		Audience: tm.Audience,
		Type:     "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(refreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, refreshTokenClaims)
	signedToken, err := token.SignedString(tm.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}
	return signedToken, nil
}

func (tm *Manager) GenerateAccessToken(userID string) (string, error) {
	now := time.Now()
	jti := uuid.New().String()

	tokenClaims := &Claims{
		UserID:   userID,
		Issuer:   tm.Issuer,
		Audience: tm.Audience,
		Type:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, tokenClaims)
	signedToken, err := token.SignedString(tm.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}
	return signedToken, nil
}

func (tm *Manager) GenerateTokens(userID string) (string, string, error) {
	refreshToken, err := tm.GenerateRefreshToken(userID)
	if err != nil {
		return "", "", err
	}
	accessToken, err := tm.GenerateAccessToken(userID)
	if err != nil {
		return "", "", err
	}
	return refreshToken, accessToken, nil
}

func (tm *Manager) GetPublicToken() *ecdsa.PublicKey {
	return tm.PublicKey
}

func validateSigningMethod(token *jwt.Token) error {
	if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
		return fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return nil
}

func (tm *Manager) getKeyVerificationFunction() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if err := validateSigningMethod(token); err != nil {
			return nil, err
		}
		return tm.PublicKey, nil
	}
}

func (tm *Manager) ValidateRefreshToken(
	ctx context.Context,
	refreshTokenString string,
) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshTokenString, claims, tm.getKeyVerificationFunction())

	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid refresh token: token is not valid")
	}

	if claims.Type != "refresh" {
		return nil, errors.New("invalid token type: not a refresh token")
	}

	if claims.UserID == "" {
		return nil, errors.New("invalid refresh token: missing user ID")
	}

	_, err = tm.RedisClient.Get(ctx, claims.ID).Result()
	if err == nil {
		return nil, errors.New("invalid refresh token: token has been blacklisted")
	}
	if !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("failed to check refresh token blacklist: %w", err)
	}

	return claims, nil
}

func (tm *Manager) ValidateAccessToken(accessTokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(accessTokenString, claims, tm.getKeyVerificationFunction())

	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid access token: token is not valid")
	}

	if claims.Type != "access" {
		return nil, errors.New("invalid token type: not an access token")
	}

	if claims.UserID == "" {
		return nil, errors.New("invalid access token: missing user ID")
	}

	return claims, nil
}

func (tm *Manager) BlacklistJTI(ctx context.Context, jti string, expTimestamp int64) error {
	expirationTime := time.Unix(expTimestamp, 0)

	if time.Now().After(expirationTime) {
		return nil
	}

	ttl := time.Until(expirationTime)

	err := tm.RedisClient.Set(ctx, jti, "blacklisted", ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to blacklist JTI %s: %w", jti, err)
	}
	return nil
}
