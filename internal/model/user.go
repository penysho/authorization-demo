package model

import "github.com/golang-jwt/jwt/v5"

// User はユーザー情報を表すモデル
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role"`
	Age      int    `json:"age"`
}

// UserRequest はABACで使用するリクエスト用のユーザー構造体
type UserRequest struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Age      int    `json:"age"`
}

// JWTClaims はJWTトークンのクレーム
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Age      int    `json:"age"`
	jwt.RegisteredClaims
}

// LoginRequest はログインリクエスト
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse はログインレスポンス
type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
