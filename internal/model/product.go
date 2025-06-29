package model

import (
	"time"
)

// Product は商品情報を表すモデル
type Product struct {
	ID          string    `json:"id" gorm:"type:varchar(36);primaryKey"`
	Name        string    `json:"name" gorm:"type:varchar(255);not null"`
	Description string    `json:"description" gorm:"type:text"`
	Price       float64   `json:"price" gorm:"type:decimal(10,2);not null"`
	AgeLimit    int       `json:"age_limit" gorm:"type:int;default:0"`        // 年齢制限（ABACで使用）
	Category    string    `json:"category" gorm:"type:varchar(100)"`          // 商品カテゴリ（ABACで使用）
	Rating      string    `json:"rating" gorm:"type:varchar(10)"`             // 商品レーティング（R, PG-13, etc.）
	Region      string    `json:"region" gorm:"type:varchar(255)"`            // 地域制限（ABACで使用、カンマ区切り）
	IsAdult     bool      `json:"is_adult" gorm:"type:boolean;default:false"` // 成人向けコンテンツフラグ
	CreatedAt   time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

// ProductRequest は商品の作成・更新リクエスト
type ProductRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Price       float64  `json:"price" binding:"required"`
	AgeLimit    int      `json:"age_limit"`
	Category    string   `json:"category"`
	Rating      string   `json:"rating"`
	Region      []string `json:"region"`
	IsAdult     bool     `json:"is_adult"`
}

// ProductListResponse は商品一覧のレスポンス
type ProductListResponse struct {
	Products   []Product `json:"products"`
	Total      int       `json:"total"`
	Page       int       `json:"page"`
	Limit      int       `json:"limit"`
	TotalPages int       `json:"total_pages"`
	TotalItems int       `json:"total_items"`
}

// ProductABACContext はABAC用の商品コンテキスト
type ProductABACContext struct {
	ID       string `json:"id"`
	AgeLimit int    `json:"age_limit"`
	Category string `json:"category"`
	Rating   string `json:"rating"`
	Region   string `json:"region"`
	IsAdult  bool   `json:"is_adult"`
}

// EnvironmentContext はABAC用の環境コンテキスト
type EnvironmentContext struct {
	Time     time.Time `json:"time"`
	Location string    `json:"location"`
	Device   string    `json:"device"`
}

// ABACRequest はABACチェック用のリクエスト構造体
type ABACRequest struct {
	User        *UserRequest        `json:"user"`
	Product     *ProductABACContext `json:"product"`
	Action      string              `json:"action"`
	Environment *EnvironmentContext `json:"environment"`
}
