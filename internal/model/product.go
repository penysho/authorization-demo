package model

import "time"

// Product は商品情報を表すモデル
type Product struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Price       float64   `json:"price"`
	AgeLimit    int       `json:"age_limit"` // 年齢制限（ABACで使用）
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ProductRequest は商品の作成・更新リクエスト
type ProductRequest struct {
	Name        string  `json:"name" binding:"required"`
	Description string  `json:"description"`
	Price       float64 `json:"price" binding:"required"`
	AgeLimit    int     `json:"age_limit"`
}

// ProductListResponse は商品一覧のレスポンス
type ProductListResponse struct {
	Products []Product `json:"products"`
	Total    int       `json:"total"`
}
