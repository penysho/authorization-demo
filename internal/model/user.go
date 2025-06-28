package model

import "github.com/golang-jwt/jwt/v5"

// User はユーザー情報を表すモデル
type User struct {
	ID       string `json:"id" gorm:"type:varchar(36);primaryKey"`
	Username string `json:"username" gorm:"type:varchar(100);uniqueIndex;not null"`
	Password string `json:"password,omitempty" gorm:"type:varchar(255);not null"`
	Role     string `json:"role" gorm:"type:varchar(50);not null"`
	Age      int    `json:"age" gorm:"type:int;default:0"`
	Location string `json:"location" gorm:"type:varchar(100)"`         // ユーザーの所在地（ABACで使用）
	Premium  bool   `json:"premium" gorm:"type:boolean;default:false"` // プレミアム会員フラグ（ABACで使用）
	VIPLevel int    `json:"vip_level" gorm:"type:int;default:0"`       // VIPレベル（ABACで使用）
}

// UserRequest はABACで使用するリクエスト用のユーザー構造体
type UserRequest struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Age      int    `json:"age"`
	Location string `json:"location"`
	Premium  bool   `json:"premium"`
	VIPLevel int    `json:"vip_level"`
}

// JWTClaims はJWTトークンのクレーム
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Age      int    `json:"age"`
	Location string `json:"location"`
	Premium  bool   `json:"premium"`
	VIPLevel int    `json:"vip_level"`
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
