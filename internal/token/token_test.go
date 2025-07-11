package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Sif3r/auth-service/internal/config"
	"github.com/Sif3r/auth-service/internal/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeys(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func createTempKeyFiles(t *testing.T, privateKey, publicKey []byte) (string, string) {
	t.Helper()
	tmpPrivateFile, err := os.CreateTemp(t.TempDir(), "test_private_key_*.pem")
	require.NoError(t, err)
	defer tmpPrivateFile.Close()
	_, err = tmpPrivateFile.Write(privateKey)
	require.NoError(t, err)
	privateKeyPath := tmpPrivateFile.Name()

	tmpPublicFile, err := os.CreateTemp(t.TempDir(), "test_public_key_*.pem")
	require.NoError(t, err)
	defer tmpPublicFile.Close()
	_, err = tmpPublicFile.Write(publicKey)
	require.NoError(t, err)
	publicKeyPath := tmpPublicFile.Name()

	return privateKeyPath, publicKeyPath
}

type mockRedisClient struct {
	data map[string]string
	ttl  map[string]time.Duration
	err  error
}

func newMockRedisClient() *mockRedisClient {
	return &mockRedisClient{
		data: make(map[string]string),
		ttl:  make(map[string]time.Duration),
	}
}

func (m *mockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	if m.err != nil {
		cmd.SetErr(m.err)
	} else {
		cmd.SetVal("PONG")
	}
	return cmd
}

func (m *mockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)
	if m.err != nil {
		cmd.SetErr(m.err)
		return cmd
	}
	val, ok := m.data[key]
	if !ok {
		cmd.SetErr(redis.Nil)
	} else {
		cmd.SetVal(val)
	}
	return cmd
}

func (m *mockRedisClient) Set(
	ctx context.Context,
	key string,
	value any,
	expiration time.Duration,
) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	if m.err != nil {
		cmd.SetErr(m.err)
		return cmd
	}
	m.data[key] = value.(string)
	m.ttl[key] = expiration
	cmd.SetVal("OK")
	return cmd
}

func TestLoadAndParsePrivateKey_Success(t *testing.T) {
	privateKey, _ := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

	tmpfile, err := os.CreateTemp(t.TempDir(), "test_private_key_*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write(privatePEM)
	require.NoError(t, err)
	tmpfile.Close()

	loadedKey, err := token.LoadAndParsePrivateKey(tmpfile.Name())
	require.NoError(t, err)
	assert.NotNil(t, loadedKey)
	assert.True(t, privateKey.PublicKey.Equal(&loadedKey.PublicKey))
}

func TestLoadAndParsePrivateKey_FileNotFound(t *testing.T) {
	_, err := token.LoadAndParsePrivateKey("non_existent_private_key.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")
}

func TestLoadAndParsePublicKey_Success(t *testing.T) {
	_, publicKey := generateTestKeys(t)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})

	tmpfile, err := os.CreateTemp(t.TempDir(), "test_public_key_*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write(publicPEM)
	require.NoError(t, err)
	tmpfile.Close()

	loadedKey, err := token.LoadAndParsePublicKey(tmpfile.Name())
	require.NoError(t, err)
	assert.NotNil(t, loadedKey)
	assert.True(t, publicKey.Equal(loadedKey))
}

func TestLoadAndParsePublicKey_FileNotFound(t *testing.T) {
	_, err := token.LoadAndParsePublicKey("non_existent_public_key.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")
}

func TestNewTokenManager_Success(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)

	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()

	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)
	assert.NotNil(t, tm)
	assert.Equal(t, cfg.Issuer, tm.Issuer)
	assert.Equal(t, cfg.Audience, tm.Audience)
	assert.NotNil(t, tm.PrivateKey)
	assert.NotNil(t, tm.PublicKey)
	assert.Equal(t, redisClient, tm.RedisClient)
}

func TestNewTokenManager_LoadPrivateKeyFailure(t *testing.T) {
	_, publicKey := generateTestKeys(t)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	_, publicKeyPath := createTempKeyFiles(
		t,
		[]byte("invalid private key"),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)

	cfg := config.Config{
		PrivateKeyPath: "non_existent.pem",
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()

	tm, err := token.NewTokenManager(cfg, redisClient)
	require.Error(t, err)
	assert.Nil(t, tm)
	assert.Contains(t, err.Error(), "failed to load private key")
}

func TestNewTokenManager_LoadPublicKeyFailure(t *testing.T) {
	privateKey, _ := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPath, _ := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		[]byte("invalid public key"),
	)

	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  "non_existent.pem",
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()

	tm, err := token.NewTokenManager(cfg, redisClient)
	require.Error(t, err)
	assert.Nil(t, tm)
	assert.Contains(t, err.Error(), "failed to load public key")
}

func TestGenerateRefreshToken_Success(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	userID := "some-user-id"
	refreshToken, err := tm.GenerateRefreshToken(userID)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	claims := &token.Claims{}
	jwtToken, err := jwt.ParseWithClaims(refreshToken, claims, func(_ *jwt.Token) (any, error) {
		return publicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, jwtToken.Valid)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "refresh", claims.Type)
	assert.Equal(t, cfg.Issuer, claims.Issuer)
	assert.Equal(t, cfg.Audience, claims.Audience)
	assert.WithinDuration(t, time.Now().Add(7*24*time.Hour), claims.ExpiresAt.Time, 5*time.Second)
}

func TestGenerateAccessToken_Success(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	userID := "some-user-id"
	accessToken, err := tm.GenerateAccessToken(userID)
	require.NoError(t, err)
	assert.NotEmpty(t, accessToken)

	claims := &token.Claims{}
	jwtToken, err := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (any, error) {
		return publicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, jwtToken.Valid)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "access", claims.Type)
	assert.Equal(t, cfg.Issuer, claims.Issuer)
	assert.Equal(t, cfg.Audience, claims.Audience)
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), claims.ExpiresAt.Time, 5*time.Second)
}

func TestGenerateTokens_Success(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	userID := "some-user-id"
	refreshToken, accessToken, err := tm.GenerateTokens(userID)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.NotEmpty(t, accessToken)

	keyFunc := func(_ *jwt.Token) (any, error) {
		return publicKey, nil
	}

	refreshClaims := &token.Claims{}
	refreshTkn, err := jwt.ParseWithClaims(refreshToken, refreshClaims, keyFunc)
	require.NoError(t, err)
	assert.True(t, refreshTkn.Valid)
	assert.Equal(t, "refresh", refreshClaims.Type)

	accessClaims := &token.Claims{}
	accessTkn, err := jwt.ParseWithClaims(accessToken, accessClaims, keyFunc)
	require.NoError(t, err)
	assert.True(t, accessTkn.Valid)
	assert.Equal(t, "access", accessClaims.Type)
}

func TestGetPublicToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	retrievedPublicKey := tm.GetPublicToken()
	assert.NotNil(t, retrievedPublicKey)
	assert.Equal(t, publicKey, retrievedPublicKey)
}

func TestValidateRefreshToken_ValidToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	userID := "test-user-id"
	refreshToken, err := tm.GenerateRefreshToken(userID)
	require.NoError(t, err)

	ctx := t.Context()
	claims, err := tm.ValidateRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "refresh", claims.Type)
}

func TestValidateRefreshToken_ExpiredToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	now := time.Now()
	expiredClaims := &token.Claims{
		UserID:   "some-user-id",
		Issuer:   tm.Issuer,
		Audience: tm.Audience,
		Type:     "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ID:        "expired-jti",
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodES256, expiredClaims)
	signedExpiredToken, err := expiredToken.SignedString(tm.PrivateKey)
	require.NoError(t, err)

	ctx := t.Context()
	_, err = tm.ValidateRefreshToken(ctx, signedExpiredToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestValidateRefreshToken_InvalidSignature(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	otherPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	claims := &token.Claims{
		UserID:   "some-user-id",
		Issuer:   tm.Issuer,
		Audience: tm.Audience,
		Type:     "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "some-jti",
		},
	}
	badToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedBadToken, err := badToken.SignedString(otherPrivateKey)
	require.NoError(t, err)

	ctx := t.Context()
	_, err = tm.ValidateRefreshToken(ctx, signedBadToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "crypto/ecdsa: verification error")
}

func TestValidateRefreshToken_WrongTokenType(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	userID := "test-user-id"
	accessToken, err := tm.GenerateAccessToken(userID) // This is an access token
	require.NoError(t, err)

	ctx := t.Context()
	_, err = tm.ValidateRefreshToken(ctx, accessToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token type: not a refresh token")
}

func TestValidateRefreshToken_MissingUserIDClaim(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	now := time.Now()
	claims := &token.Claims{
		Issuer:   tm.Issuer,
		Audience: tm.Audience,
		Type:     "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "some-jti",
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := jwtToken.SignedString(tm.PrivateKey)
	require.NoError(t, err)

	ctx := t.Context()
	_, err = tm.ValidateRefreshToken(ctx, signedToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token: missing user ID")
}

func TestValidateRefreshToken_BlacklistedToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	userID := "test-user-id"
	refreshToken, err := tm.GenerateRefreshToken(userID)
	require.NoError(t, err)

	// First validate to get claims
	claims, err := tm.ValidateRefreshToken(t.Context(), refreshToken)
	require.NoError(t, err)

	// Blacklist the token
	ctx := t.Context()
	err = tm.BlacklistJTI(ctx, claims.ID, claims.ExpiresAt.Time.Unix())
	require.NoError(t, err)

	// Now validation should fail
	_, err = tm.ValidateRefreshToken(ctx, refreshToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token: token has been blacklisted")
}

func TestValidateRefreshToken_RedisError(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := createTempKeyFiles(
		t,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}),
	)
	cfg := config.Config{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Issuer:         "test-issuer",
		Audience:       []string{"test-audience"},
	}
	redisClient := newMockRedisClient()
	tm, err := token.NewTokenManager(cfg, redisClient)
	require.NoError(t, err)

	userID := "test-user-id"
	refreshToken, err := tm.GenerateRefreshToken(userID)
	require.NoError(t, err)

	redisClient.err = errors.New("simulated redis error")

	ctx := t.Context()
	_, err = tm.ValidateRefreshToken(ctx, refreshToken)
	require.Error(t, err)
	assert.Contains(
		t,
		err.Error(),
		"failed to check refresh token blacklist: simulated redis error",
	)
}

func TestBlacklistJTI_Success(t *testing.T) {
	redisClient := newMockRedisClient()
	tm := &token.Manager{RedisClient: redisClient}

	jti := "some-jti"
	expTimestamp := time.Now().Add(time.Hour).Unix()
	ctx := t.Context()

	err := tm.BlacklistJTI(ctx, jti, expTimestamp)
	require.NoError(t, err)

	val, err := redisClient.Get(ctx, jti).Result()
	require.NoError(t, err)
	assert.Equal(t, "blacklisted", val)
	assert.Greater(t, redisClient.ttl[jti], 0*time.Second)
}

func TestBlacklistJTI_TokenAlreadyExpired(t *testing.T) {
	redisClient := newMockRedisClient()
	tm := &token.Manager{RedisClient: redisClient}

	jti := "expired-jti"
	expTimestamp := time.Now().Add(-time.Hour).Unix()
	ctx := t.Context()

	err := tm.BlacklistJTI(ctx, jti, expTimestamp)
	require.NoError(t, err)

	_, err = redisClient.Get(ctx, jti).Result()
	require.ErrorIs(t, err, redis.Nil)
}

func TestBlacklistJTI_RedisSetError(t *testing.T) {
	redisClient := newMockRedisClient()
	redisClient.err = errors.New("simulated redis set error")
	tm := &token.Manager{RedisClient: redisClient}

	jti := "some-jti"
	expTimestamp := time.Now().Add(time.Hour).Unix()
	ctx := t.Context()

	err := tm.BlacklistJTI(ctx, jti, expTimestamp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to blacklist JTI some-jti: simulated redis set error")
}
