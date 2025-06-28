package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authorization-demo/internal/model"

	"gorm.io/gorm"
)

// ProductService は商品サービスのインターフェース
type ProductService interface {
	CreateProduct(ctx context.Context, req *model.ProductRequest, createdBy string) (*model.Product, error)
	GetProduct(ctx context.Context, id string) (*model.Product, error)
	GetProductsForUser(ctx context.Context, user *model.User, filters ProductFilters) ([]model.Product, error)
	UpdateProduct(ctx context.Context, id string, req *model.ProductRequest, updatedBy string) (*model.Product, error)
	DeleteProduct(ctx context.Context, id string, deletedBy string) error

	// ABAC関連機能
	SetProductPolicy(ctx context.Context, productID string, policy ProductPolicy, createdBy string) error
	GetProductPolicy(ctx context.Context, productID string) (*ProductPolicy, error)
	CheckProductAccess(ctx context.Context, userID, productID, action string) (bool, error)
}

// ProductFilters は商品フィルタリング条件
type ProductFilters struct {
	Category  string
	MinPrice  float64
	MaxPrice  float64
	AgeLimit  int
	Region    string
	OnlyAdult *bool
	VIPLevel  int
}

// productServiceImpl は商品サービスの実装
type productServiceImpl struct {
	db      *gorm.DB
	authSvc *AuthorizationService
}

// NewProductService は新しい商品サービスを作成
func NewProductService(db *gorm.DB, authSvc *AuthorizationService) ProductService {
	return &productServiceImpl{
		db:      db,
		authSvc: authSvc,
	}
}

// CreateProduct は新しい商品を作成
func (s *productServiceImpl) CreateProduct(ctx context.Context, req *model.ProductRequest, createdBy string) (*model.Product, error) {
	product := &model.Product{
		ID:          generateProductID(),
		Name:        req.Name,
		Description: req.Description,
		Price:       req.Price,
		AgeLimit:    req.AgeLimit,
		Category:    req.Category,
		Rating:      req.Rating,
		Region:      strings.Join(req.Region, ","),
		IsAdult:     req.IsAdult,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.db.WithContext(ctx).Create(product).Error; err != nil {
		return nil, fmt.Errorf("failed to create product: %w", err)
	}

	return product, nil
}

// GetProduct は商品を取得
func (s *productServiceImpl) GetProduct(ctx context.Context, id string) (*model.Product, error) {
	var product model.Product
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&product).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("product not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get product: %w", err)
	}
	return &product, nil
}

// GetProductsForUser はユーザーがアクセス可能な商品一覧を取得
func (s *productServiceImpl) GetProductsForUser(ctx context.Context, user *model.User, filters ProductFilters) ([]model.Product, error) {
	var products []model.Product
	query := s.db.WithContext(ctx).Model(&model.Product{})

	// 基本フィルタ
	if filters.Category != "" {
		query = query.Where("category = ?", filters.Category)
	}
	if filters.MinPrice > 0 {
		query = query.Where("price >= ?", filters.MinPrice)
	}
	if filters.MaxPrice > 0 {
		query = query.Where("price <= ?", filters.MaxPrice)
	}

	// ユーザーの年齢に基づくフィルタ
	if user.Age > 0 {
		query = query.Where("age_limit <= ? OR age_limit = 0", user.Age)
	}

	// 成人向けコンテンツフィルタ
	if user.Age < 18 {
		query = query.Where("is_adult = false")
	} else if filters.OnlyAdult != nil && *filters.OnlyAdult {
		query = query.Where("is_adult = true")
	}

	// 地域フィルタはABACレベルで処理するため、ここではスキップ
	// （基本的なDBフィルタリングは年齢と成人向けコンテンツのみ）

	if err := query.Find(&products).Error; err != nil {
		return nil, fmt.Errorf("failed to get products: %w", err)
	}

	// ABACによる詳細フィルタリング
	var filteredProducts []model.Product
	for _, product := range products {
		accessCtx := &ProductAccessContext{
			UserID:    user.ID,
			User:      user,
			ProductID: product.ID,
			Product:   &product,
			Action:    "read",
		}

		allowed, err := s.authSvc.CheckProductAccess(accessCtx)
		if err != nil {
			fmt.Printf("Warning: failed to check access for product %s: %v\n", product.ID, err)
			continue
		}

		if allowed {
			filteredProducts = append(filteredProducts, product)
		}
	}

	return filteredProducts, nil
}

// UpdateProduct は商品を更新
func (s *productServiceImpl) UpdateProduct(ctx context.Context, id string, req *model.ProductRequest, updatedBy string) (*model.Product, error) {
	var product model.Product
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&product).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("product not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get product: %w", err)
	}

	// 商品情報を更新
	product.Name = req.Name
	product.Description = req.Description
	product.Price = req.Price
	product.AgeLimit = req.AgeLimit
	product.Category = req.Category
	product.Rating = req.Rating
	product.Region = strings.Join(req.Region, ",")
	product.IsAdult = req.IsAdult
	product.UpdatedAt = time.Now()

	if err := s.db.WithContext(ctx).Save(&product).Error; err != nil {
		return nil, fmt.Errorf("failed to update product: %w", err)
	}

	// ポリシーの更新（必要に応じて）
	if err := s.updateProductPolicy(ctx, &product, updatedBy); err != nil {
		fmt.Printf("Warning: failed to update policy for product %s: %v\n", product.ID, err)
	}

	return &product, nil
}

// DeleteProduct は商品を削除
func (s *productServiceImpl) DeleteProduct(ctx context.Context, id string, deletedBy string) error {
	if err := s.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Product{}).Error; err != nil {
		return fmt.Errorf("failed to delete product: %w", err)
	}

	// 関連するポリシーも削除
	if err := s.deleteProductPolicy(ctx, id, deletedBy); err != nil {
		fmt.Printf("Warning: failed to delete policy for product %s: %v\n", id, err)
	}

	return nil
}

// SetProductPolicy は商品固有のポリシーを設定
func (s *productServiceImpl) SetProductPolicy(ctx context.Context, productID string, policy ProductPolicy, createdBy string) error {
	return s.authSvc.AddProductPolicy(ctx, productID, policy, createdBy)
}

// GetProductPolicy は商品のポリシーを取得
func (s *productServiceImpl) GetProductPolicy(ctx context.Context, productID string) (*ProductPolicy, error) {
	// TODO: ポリシーストアから商品固有のポリシーを取得
	// 現在は簡略化のため、デフォルトポリシーを返す
	product, err := s.GetProduct(ctx, productID)
	if err != nil {
		return nil, err
	}

	// VIPレベル要件の簡易計算（ハードコードではなく、設定ベース）
	vipLevel := 0
	switch product.Category {
	case "luxury":
		vipLevel = 3
	case "exclusive":
		vipLevel = 5
	case "vip-only":
		vipLevel = 2
	}

	return &ProductPolicy{
		SubjectRule: fmt.Sprintf("r.sub.Age >= %d", product.AgeLimit),
		Action:      "read",
		AgeLimit:    product.AgeLimit,
		Category:    product.Category,
		IsAdult:     product.IsAdult,
		Region:      product.Region,
		VIPLevel:    vipLevel,
	}, nil
}

// CheckProductAccess は商品アクセス権限をチェック
func (s *productServiceImpl) CheckProductAccess(ctx context.Context, userID, productID, action string) (bool, error) {
	// ユーザー情報を取得
	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return false, fmt.Errorf("failed to get user: %w", err)
	}

	// 商品情報を取得
	product, err := s.GetProduct(ctx, productID)
	if err != nil {
		return false, err
	}

	// アクセス権限をチェック
	accessCtx := &ProductAccessContext{
		UserID:    userID,
		User:      &user,
		ProductID: productID,
		Product:   product,
		Action:    action,
	}

	return s.authSvc.CheckProductAccess(accessCtx)
}

// updateProductPolicy は商品更新時にポリシーを更新
func (s *productServiceImpl) updateProductPolicy(ctx context.Context, product *model.Product, updatedBy string) error {
	// 既存のポリシーを削除して新しいポリシーを設定
	if err := s.deleteProductPolicy(ctx, product.ID, updatedBy); err != nil {
		return err
	}
	return nil
}

// deleteProductPolicy は商品のポリシーを削除
func (s *productServiceImpl) deleteProductPolicy(ctx context.Context, productID, deletedBy string) error {
	// TODO: ポリシーストアから商品固有のポリシーを削除
	// 現在は簡略化のため、ログ出力のみ
	fmt.Printf("Product policy deleted for product %s by %s\n", productID, deletedBy)
	return nil
}

// generateProductID は商品IDを生成
func generateProductID() string {
	return fmt.Sprintf("prod_%d", time.Now().UnixNano())
}
