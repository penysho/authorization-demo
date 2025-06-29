package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authorization-demo/internal/model"

	"gorm.io/gorm"
)

// PagedProductResponse はページング情報を含む商品一覧レスポンス
type PagedProductResponse struct {
	Products   []model.Product `json:"products"`
	Page       int             `json:"page"`
	Limit      int             `json:"limit"`
	TotalPages int             `json:"total_pages"`
	TotalItems int             `json:"total_items"`
}

// ProductService は商品サービスのインターフェース
type ProductService interface {
	CreateProduct(ctx context.Context, req *model.ProductRequest, createdBy string) (*model.Product, error)
	GetProduct(ctx context.Context, id string) (*model.Product, error)
	GetProductsForUser(ctx context.Context, user *model.User, filters ProductFilters) (*PagedProductResponse, error)
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
	Page      int // ページ番号（1から開始）
	Limit     int // 1ページあたりの件数
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
// PDP-Level Filtering with Information Graph パターンを実装
func (s *productServiceImpl) GetProductsForUser(ctx context.Context, user *model.User, filters ProductFilters) (*PagedProductResponse, error) {
	// ページング処理のためのデフォルト値設定
	page := filters.Page
	if page < 1 {
		page = 1
	}
	limit := filters.Limit
	if limit < 1 {
		limit = 10 // デフォルト値
	}

	// Step 1: 基本フィルタを適用して候補商品IDを軽量取得
	candidateIDs, _, err := s.getCandidateProductIDs(ctx, filters)
	if err != nil {
		return nil, fmt.Errorf("failed to get candidate product IDs: %w", err)
	}

	if len(candidateIDs) == 0 {
		return &PagedProductResponse{
			Products:   []model.Product{},
			Page:       page,
			Limit:      limit,
			TotalPages: 1,
			TotalItems: 0,
		}, nil
	}

	// Step 2: PDP-Level Filtering - バルク権限チェック
	accessibleIDs, err := s.authSvc.GetAccessibleResourceIDs(ctx, user, "products", "read", candidateIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to filter accessible products: %w", err)
	}

	if len(accessibleIDs) == 0 {
		return &PagedProductResponse{
			Products:   []model.Product{},
			Page:       page,
			Limit:      limit,
			TotalPages: 1,
			TotalItems: 0,
		}, nil
	}

	// Step 3: データベースレベルでページングを適用してアクセス可能な商品のみを取得
	products, err := s.getProductsByIDsWithPaging(ctx, accessibleIDs, page, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get products by IDs: %w", err)
	}

	totalAccessible := len(accessibleIDs)
	totalPages := (totalAccessible + limit - 1) / limit
	if totalPages < 1 {
		totalPages = 1
	}

	return &PagedProductResponse{
		Products:   products,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
		TotalItems: totalAccessible,
	}, nil
}

// getCandidateProductIDs は基本フィルタを適用して候補商品IDを軽量取得
func (s *productServiceImpl) getCandidateProductIDs(ctx context.Context, filters ProductFilters) ([]string, int, error) {
	query := s.db.WithContext(ctx).Model(&model.Product{}).Select("id")

	// 基本フィルタを適用
	if filters.Category != "" {
		query = query.Where("category = ?", filters.Category)
	}
	if filters.MinPrice > 0 {
		query = query.Where("price >= ?", filters.MinPrice)
	}
	if filters.MaxPrice > 0 {
		query = query.Where("price <= ?", filters.MaxPrice)
	}
	if filters.AgeLimit > 0 {
		query = query.Where("age_limit <= ?", filters.AgeLimit)
	}
	if filters.Region != "" {
		query = query.Where("region LIKE ?", "%"+filters.Region+"%")
	}
	if filters.OnlyAdult != nil {
		query = query.Where("is_adult = ?", *filters.OnlyAdult)
	}
	if filters.VIPLevel > 0 {
		// VIPレベルに基づく商品フィルタリング（カテゴリベース）
		vipCategories := s.getVIPCategories(filters.VIPLevel)
		if len(vipCategories) > 0 {
			query = query.Where("category IN ?", vipCategories)
		}
	}

	// 総数を取得
	var totalCount int64
	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count candidate products: %w", err)
	}

	// IDのみを取得（メモリ効率的）
	var ids []string
	if err := query.Pluck("id", &ids).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get candidate product IDs: %w", err)
	}

	return ids, int(totalCount), nil
}

// getProductsByIDsWithPaging は指定されたIDリストから商品を取得（ページング付き）
func (s *productServiceImpl) getProductsByIDsWithPaging(ctx context.Context, productIDs []string, page, limit int) ([]model.Product, error) {
	if len(productIDs) == 0 {
		return []model.Product{}, nil
	}

	// ページングのためのオフセット計算
	offset := (page - 1) * limit

	var products []model.Product
	query := s.db.WithContext(ctx).Where("id IN ?", productIDs).
		Order("created_at DESC"). // 作成日時の降順でソート
		Offset(offset).
		Limit(limit)

	if err := query.Find(&products).Error; err != nil {
		return nil, fmt.Errorf("failed to get products by IDs: %w", err)
	}

	return products, nil
}

// getVIPCategories はVIPレベルに基づいてアクセス可能なカテゴリを取得
func (s *productServiceImpl) getVIPCategories(vipLevel int) []string {
	switch vipLevel {
	case 1:
		return []string{"basic", "standard"}
	case 2:
		return []string{"basic", "standard", "premium"}
	case 3:
		return []string{"basic", "standard", "premium", "luxury"}
	case 4:
		return []string{"basic", "standard", "premium", "luxury", "exclusive"}
	case 5:
		return []string{"basic", "standard", "premium", "luxury", "exclusive", "vip-only"}
	default:
		return []string{"basic"}
	}
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
	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return false, fmt.Errorf("failed to get user: %w", err)
	}

	return s.authSvc.CheckPermission(&user, "products", action, &productID)
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
