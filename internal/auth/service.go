package auth

import (
	"context"
	"errors"
	"time"

	"authorization-demo/internal/model"
	"authorization-demo/internal/service"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// JWTSecret は開発用の秘密鍵（本番環境では環境変数から取得すべき）
	JWTSecret = []byte("your-secret-key")

	// ErrInvalidCredentials は認証失敗エラー
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrInvalidToken は無効なトークンエラー
	ErrInvalidToken = errors.New("invalid token")
)

// Service は認証サービス
type Service struct {
	userService service.UserService
}

// NewService は新しい認証サービスを作成
func NewService(userService service.UserService) *Service {
	return &Service{userService: userService}
}

// Login はユーザー認証とJWTトークン生成を行う
func (s *Service) Login(username, password string) (*model.LoginResponse, error) {
	ctx := context.Background()

	// データベースからユーザーを認証
	user, err := s.userService.ValidatePassword(ctx, username, password)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// JWTトークンを生成
	token, err := s.generateJWT(user)
	if err != nil {
		return nil, err
	}

	return &model.LoginResponse{
		Token: token,
		User:  *user,
	}, nil
}

// ValidateToken はJWTトークンを検証してユーザー情報を返す
func (s *Service) ValidateToken(tokenString string) (*model.User, error) {
	token, err := jwt.ParseWithClaims(tokenString, &model.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return JWTSecret, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*model.JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// ユーザー情報を構築
	user := &model.User{
		ID:       claims.UserID,
		Username: claims.Username,
		Role:     claims.Role,
		Age:      claims.Age,
		Location: claims.Location,
		Premium:  claims.Premium,
		VIPLevel: claims.VIPLevel,
	}

	return user, nil
}

// generateJWT はJWTトークンを生成
func (s *Service) generateJWT(user *model.User) (string, error) {
	claims := &model.JWTClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Age:      user.Age,
		Location: user.Location,
		Premium:  user.Premium,
		VIPLevel: user.VIPLevel,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JWTSecret)
}
