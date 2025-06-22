package service

import (
	"errors"
	"fmt"
	"time"

	"authorization-demo/internal/model"
)

var (
	// ErrProductNotFound は商品が見つからないエラー
	ErrProductNotFound = errors.New("product not found")
)

// ProductService は商品サービス
type ProductService struct {
	products map[string]*model.Product // 簡易的な商品ストア
}

// NewProductService は新しい商品サービスを作成
func NewProductService() *ProductService {
	now := time.Now()

	// サンプル商品データを作成
	products := map[string]*model.Product{
		"1": {
			ID:          "1",
			Name:        "一般商品",
			Description: "年齢制限なしの一般的な商品",
			Price:       1000.0,
			AgeLimit:    0,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		"2": {
			ID:          "2",
			Name:        "成人向け商品",
			Description: "20歳以上限定の商品",
			Price:       2000.0,
			AgeLimit:    20,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		"3": {
			ID:          "3",
			Name:        "18歳以上商品",
			Description: "18歳以上限定の商品",
			Price:       1500.0,
			AgeLimit:    18,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}

	return &ProductService{products: products}
}

// GetAllProducts は全ての商品を取得
func (s *ProductService) GetAllProducts() ([]*model.Product, error) {
	products := make([]*model.Product, 0, len(s.products))
	for _, product := range s.products {
		products = append(products, product)
	}
	return products, nil
}

// GetProductByID はIDで商品を取得
func (s *ProductService) GetProductByID(id string) (*model.Product, error) {
	product, exists := s.products[id]
	if !exists {
		return nil, ErrProductNotFound
	}
	return product, nil
}

// UpdateProduct は商品を更新
func (s *ProductService) UpdateProduct(id string, req *model.ProductRequest) (*model.Product, error) {
	product, exists := s.products[id]
	if !exists {
		return nil, ErrProductNotFound
	}

	// 商品情報を更新
	product.Name = req.Name
	product.Description = req.Description
	product.Price = req.Price
	product.AgeLimit = req.AgeLimit
	product.UpdatedAt = time.Now()

	s.products[id] = product
	return product, nil
}

// DeleteProduct は商品を削除
func (s *ProductService) DeleteProduct(id string) error {
	if _, exists := s.products[id]; !exists {
		return ErrProductNotFound
	}

	delete(s.products, id)
	return nil
}

// CreateProduct は新しい商品を作成
func (s *ProductService) CreateProduct(req *model.ProductRequest) (*model.Product, error) {
	now := time.Now()
	id := fmt.Sprintf("%d", now.Unix()) // 簡易的なID生成

	product := &model.Product{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		Price:       req.Price,
		AgeLimit:    req.AgeLimit,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	s.products[id] = product
	return product, nil
}
