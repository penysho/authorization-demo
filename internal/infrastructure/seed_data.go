package infrastructure

import (
	"context"
	"fmt"
	"log"
	"strings"

	"authorization-demo/internal/model"
	"authorization-demo/internal/service"

	"gorm.io/gorm"
)

// SeedDataManager handles test data initialization
type SeedDataManager struct {
	db             *gorm.DB
	userService    service.UserService
	productService service.ProductService
}

// NewSeedDataManager creates a new seed data manager
func NewSeedDataManager(db *gorm.DB, userService service.UserService, productService service.ProductService) *SeedDataManager {
	return &SeedDataManager{
		db:             db,
		userService:    userService,
		productService: productService,
	}
}

// SeedAll initializes all sample data
func (s *SeedDataManager) SeedAll(policyStore service.CasbinPolicyStore) error {
	// Setup sample users
	if err := s.setupSampleUsers(); err != nil {
		return fmt.Errorf("failed to setup sample users: %w", err)
	}

	// Setup sample products
	sampleProducts, err := s.setupSampleProducts()
	if err != nil {
		return fmt.Errorf("failed to setup sample products: %w", err)
	}

	// Setup initial policies
	if err := s.setupInitialPolicies(policyStore, sampleProducts); err != nil {
		return fmt.Errorf("failed to setup initial policies: %w", err)
	}

	return nil
}

// setupSampleUsers はサンプルユーザーデータを設定
func (s *SeedDataManager) setupSampleUsers() error {
	ctx := context.Background()

	// 既存のユーザー数をチェック
	users, err := s.userService.ListUsers(ctx, service.UserFilters{})
	if err != nil {
		return fmt.Errorf("failed to check existing users: %w", err)
	}

	if len(users) > 0 {
		log.Println("Sample users already exist, skipping creation")
		return nil
	}

	// サンプルユーザーの作成
	sampleUsers := []service.CreateUserRequest{
		{
			Username: "alice",
			Password: "password123",
			Role:     "admin",
			Age:      30,
			Location: "JP",
			Premium:  true,
			VIPLevel: 5,
		},
		{
			Username: "bob",
			Password: "password123",
			Role:     "operator",
			Age:      25,
			Location: "US",
			Premium:  true,
			VIPLevel: 3,
		},
		{
			Username: "charlie",
			Password: "password123",
			Role:     "customer",
			Age:      17,
			Location: "JP",
			Premium:  false,
			VIPLevel: 0,
		},
		{
			Username: "dave",
			Password: "password123",
			Role:     "customer",
			Age:      22,
			Location: "EU",
			Premium:  false,
			VIPLevel: 1,
		},
	}

	for _, userReq := range sampleUsers {
		user, err := s.userService.CreateUser(ctx, &userReq)
		if err != nil {
			log.Printf("Warning: failed to create sample user %s: %v", userReq.Username, err)
		} else {
			log.Printf("Created sample user: %s (ID: %s)", user.Username, user.ID)
		}
	}

	log.Println("Sample user data setup completed")
	return nil
}

// setupSampleProducts はサンプル商品データを設定
func (s *SeedDataManager) setupSampleProducts() ([]*model.Product, error) {
	ctx := context.Background()

	// サンプル商品の作成（20個）
	sampleProducts := []model.ProductRequest{
		{
			Name:        "一般書籍",
			Description: "年齢制限なしの一般的な書籍",
			Price:       1500.0,
			AgeLimit:    0,
			Category:    "books",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "アルコール飲料",
			Description: "20歳以上限定のアルコール飲料",
			Price:       3000.0,
			AgeLimit:    20,
			Category:    "alcohol",
			Region:      []string{"JP", "US"},
			IsAdult:     false,
		},
		{
			Name:        "成人向けコンテンツ",
			Description: "18歳以上限定、深夜時間帯制限あり",
			Price:       2500.0,
			AgeLimit:    18,
			Category:    "adult",
			Region:      []string{"JP"},
			IsAdult:     true,
		},
		{
			Name:        "高級腕時計",
			Description: "VIPレベル3以上限定の高級商品",
			Price:       500000.0,
			AgeLimit:    0,
			Category:    "luxury",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "プレミアム会員限定商品",
			Description: "プレミアム会員のみアクセス可能",
			Price:       10000.0,
			AgeLimit:    0,
			Category:    "premium-exclusive",
			Region:      []string{"JP", "US"},
			IsAdult:     false,
		},
		{
			Name:        "地域限定商品",
			Description: "日本国内限定販売商品",
			Price:       2000.0,
			AgeLimit:    0,
			Category:    "regional",
			Region:      []string{"JP"},
			IsAdult:     false,
		},
		{
			Name:        "スマートフォン",
			Description: "最新スマートフォン",
			Price:       80000.0,
			AgeLimit:    0,
			Category:    "electronics",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "ノートパソコン",
			Description: "高性能ノートパソコン",
			Price:       120000.0,
			AgeLimit:    0,
			Category:    "electronics",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "日本酒セット",
			Description: "プレミアム日本酒セット（20歳以上）",
			Price:       15000.0,
			AgeLimit:    20,
			Category:    "alcohol",
			Region:      []string{"JP"},
			IsAdult:     false,
		},
		{
			Name:        "医学書",
			Description: "専門医学書",
			Price:       8000.0,
			AgeLimit:    0,
			Category:    "books",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "VIP限定ジュエリー",
			Description: "VIPレベル5以上限定のダイヤモンドジュエリー",
			Price:       1200000.0,
			AgeLimit:    0,
			Category:    "luxury",
			Region:      []string{"JP", "US"},
			IsAdult:     false,
		},
		{
			Name:        "ワインセット",
			Description: "フランス産高級ワイン（20歳以上）",
			Price:       25000.0,
			AgeLimit:    20,
			Category:    "alcohol",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "韓国限定商品",
			Description: "韓国地域限定商品",
			Price:       3500.0,
			AgeLimit:    0,
			Category:    "regional",
			Region:      []string{"KR"},
			IsAdult:     false,
		},
		{
			Name:        "成人向けゲーム",
			Description: "18歳以上限定のゲームソフト",
			Price:       6000.0,
			AgeLimit:    18,
			Category:    "games",
			Region:      []string{"JP", "US"},
			IsAdult:     true,
		},
		{
			Name:        "子供向け絵本",
			Description: "年齢制限なしの子供向け絵本",
			Price:       800.0,
			AgeLimit:    0,
			Category:    "books",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "オーディオ機器",
			Description: "高級オーディオシステム",
			Price:       150000.0,
			AgeLimit:    0,
			Category:    "electronics",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "スポーツウェア",
			Description: "プロ仕様スポーツウェア",
			Price:       4500.0,
			AgeLimit:    0,
			Category:    "sports",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "高級化粧品",
			Description: "プレミアム化粧品セット",
			Price:       12000.0,
			AgeLimit:    0,
			Category:    "beauty",
			Region:      []string{"JP", "US", "EU"},
			IsAdult:     false,
		},
		{
			Name:        "アメリカ限定スニーカー",
			Description: "アメリカ地域限定スニーカー",
			Price:       18000.0,
			AgeLimit:    0,
			Category:    "fashion",
			Region:      []string{"US"},
			IsAdult:     false,
		},
		{
			Name:        "VIP専用サービス",
			Description: "VIPレベル2以上限定のコンシェルジュサービス",
			Price:       50000.0,
			AgeLimit:    0,
			Category:    "vip-only",
			Region:      []string{"JP", "US"},
			IsAdult:     false,
		},
	}

	// 既存の商品をチェックして、存在しない場合のみ作成
	var existingCount int64
	if err := s.db.Model(&model.Product{}).Count(&existingCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count existing products: %w", err)
	}

	if existingCount > 0 {
		log.Println("Sample products already exist, skipping creation")
		return nil, nil
	}

	createdProducts := make([]*model.Product, 0, len(sampleProducts))
	for _, productReq := range sampleProducts {
		result, err := s.productService.CreateProduct(ctx, &productReq, "system")
		if err != nil {
			log.Printf("Warning: failed to create sample product %s: %v", productReq.Name, err)
		} else {
			log.Printf("Created sample product: %s", productReq.Name)
			createdProducts = append(createdProducts, result)
		}
	}

	log.Println("Sample product data setup completed")
	return createdProducts, nil
}

// setupInitialPolicies は初期ポリシーを設定
func (s *SeedDataManager) setupInitialPolicies(store service.CasbinPolicyStore, sampleProducts []*model.Product) error {
	ctx := context.Background()

	// RBAC policies
	policies := []model.PolicyRule{
		{
			Type:     "rbac",
			Subject:  "admin",
			Resource: "products",
			Action:   "read",
			Effect:   "allow",
		},
		{
			Type:     "rbac",
			Subject:  "admin",
			Resource: "products",
			Action:   "write",
			Effect:   "allow",
		},
		{
			Type:     "rbac",
			Subject:  "admin",
			Resource: "products",
			Action:   "delete",
			Effect:   "allow",
		},
		{
			Type:     "rbac",
			Subject:  "admin",
			Resource: "policies",
			Action:   "admin",
			Effect:   "allow",
		},
		{
			Type:     "rbac",
			Subject:  "operator",
			Resource: "products",
			Action:   "read",
			Effect:   "allow",
		},
		{
			Type:     "rbac",
			Subject:  "operator",
			Resource: "products",
			Action:   "write",
			Effect:   "allow",
		},
		{
			Type:     "rbac",
			Subject:  "customer",
			Resource: "products",
			Action:   "read",
			Effect:   "allow",
		},
	}

	abacPolicies := make([]model.PolicyRule, 0, len(sampleProducts))
	for _, product := range sampleProducts {
		// 仮のABACポリシー
		if product.IsAdult {
			abacPolicies = append(abacPolicies, model.PolicyRule{
				Type:      "abac",
				Condition: "r.sub.Age >= 18",
				Resource:  product.ID,
				Action:    "read",
				Effect:    "allow",
			})
		} else {
			abacPolicies = append(abacPolicies, model.PolicyRule{
				Type:      "abac",
				Condition: "r.sub.Age >= 0",
				Resource:  product.ID,
				Action:    "read",
				Effect:    "allow",
			})
		}
	}

	// Combine RBAC and ABAC policies
	policies = append(policies, abacPolicies...)

	// ポリシーの保存
	for _, policy := range policies {
		if err := store.SavePolicy(ctx, policy); err != nil {
			return fmt.Errorf("failed to save policy: %w", err)
		}
	}

	// Role assignments - 実際に作成されたユーザーIDを使用
	userRoles := map[string]string{
		"alice":   "admin",
		"bob":     "operator",
		"charlie": "customer",
		"dave":    "customer",
	}

	for username, role := range userRoles {
		user, err := s.userService.GetUserByUsername(ctx, username)
		if err != nil {
			log.Printf("Warning: failed to find user %s for role assignment: %v", username, err)
			continue
		}

		if err := store.AssignRole(ctx, user.ID, role); err != nil {
			// Check if this is a "already exists" error, which is fine for initial setup
			if strings.Contains(err.Error(), "already exists") {
				log.Printf("Info: Role assignment already exists for %s (%s) -> %s (this is normal)", username, user.ID, role)
			} else {
				return fmt.Errorf("failed to assign initial role: %w", err)
			}
		} else {
			log.Printf("Assigned role %s to user %s (ID: %s)", role, username, user.ID)
		}
	}

	return nil
}