package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"authorization-demo/internal/handler"
	"authorization-demo/internal/infrastructure"
	"authorization-demo/internal/middleware"
	"authorization-demo/internal/model"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func main() {
	// Initialize database connection
	dbConfig := infrastructure.DefaultDatabaseConfig()
	db, err := infrastructure.ConnectDatabase(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Perform database migration
	if err := infrastructure.MigratePolicyStoreSchema(db); err != nil {
		log.Fatalf("Failed to migrate database schema: %v", err)
	}

	// Migrate product tables
	if err := migrateProductSchema(db); err != nil {
		log.Fatalf("Failed to migrate product schema: %v", err)
	}

	// Migrate policy engine tables
	if err := infrastructure.MigratePolicyEngineSchema(db); err != nil {
		log.Fatalf("Failed to migrate policy engine schema: %v", err)
	}

	// Initialize services
	userService := service.NewUserService(db)
	authService := service.NewAuthenticationService(userService)

	casbinPolicyStore := service.NewCasbinDatabasePolicyStore(db)
	structuredPolicyEngine := service.NewPolicyEngine(db)

	// Initialize authorization service
	authzService, err := service.NewAuthorizationService(casbinPolicyStore, structuredPolicyEngine)
	if err != nil {
		log.Fatalf("Failed to initialize authorization service: %v", err)
	}

	// Initialize product service with ABAC support
	productService := service.NewProductService(db, authzService)

	// サンプルユーザーデータの設定
	if err := setupSampleUsers(userService); err != nil {
		log.Fatalf("Failed to setup sample users: %v", err)
	}

	// サンプル商品データの設定
	sampleProducts, err := setupSampleData(db, productService)
	if err != nil {
		log.Fatalf("Failed to setup sample data: %v", err)
	}

	// 初期ポリシーの設定
	if err := setupInitialPolicies(casbinPolicyStore, userService, sampleProducts); err != nil {
		log.Fatalf("Failed to setup initial policies: %v", err)
	}

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService)
	productHandler := handler.NewProductHandler(productService, authzService)
	casbinPolicyHandler := handler.NewCasbinPolicyHandler(authzService)
	structuredPolicyHandler := handler.NewStructuredPolicyHandler(structuredPolicyEngine)

	// Setup Gin router
	r := gin.Default()

	// CORS設定（開発用）
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User-ID")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Public routes
	r.POST("/api/auth/login", authHandler.Login)

	// Protected routes
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware(authService))

	// Product routes with ABAC support
	api.GET("/products",
		middleware.RequireBulkProductAccess(authzService, "read"),
		productHandler.GetProducts)
	api.GET("/products/:id",
		middleware.RequireProductAccess(authzService, productService, "read"),
		productHandler.GetProduct)
	api.PUT("/products/:id",
		middleware.RequireProductAccess(authzService, productService, "write"),
		productHandler.UpdateProduct)
	api.DELETE("/products/:id",
		middleware.RequireProductAccess(authzService, productService, "delete"),
		productHandler.DeleteProduct)
	api.POST("/products",
		middleware.RequirePermission(authzService, "products", "write"),
		productHandler.CreateProduct)

	// Casbin policy management routes (admin only)
	casbinAPI := api.Group("/casbin")
	casbinAPI.POST("/products/:id",
		middleware.RequirePermission(authzService, "policies", "admin"),
		productHandler.SetProductPolicy)
	casbinAPI.GET("/products/:id",
		middleware.RequirePermission(authzService, "policies", "admin"),
		productHandler.GetProductPolicy)
	casbinAPI.GET("/products/:id/access",
		middleware.RequireBulkProductAccess(authzService, "read"),
		productHandler.CheckProductAccess)
	casbinAPI.POST("/policies",
		middleware.RequirePermission(authzService, "policies", "admin"),
		casbinPolicyHandler.CreatePolicy)
	casbinAPI.POST("/roles/assign",
		middleware.RequirePermission(authzService, "policies", "admin"),
		casbinPolicyHandler.AssignRole)
	casbinAPI.GET("/audit-log",
		middleware.RequirePermission(authzService, "policies", "admin"),
		casbinPolicyHandler.GetAuditLog)

	// Structured policy management routes (admin only)
	structuredAPI := api.Group("/structured-policy")
	structuredAPI.POST("/products/:id",
		middleware.RequirePermission(authzService, "policies", "admin"),
		structuredPolicyHandler.CreateProductPolicy)
	structuredAPI.GET("/products/:id",
		middleware.RequirePermission(authzService, "policies", "admin"),
		structuredPolicyHandler.GetProductPolicy)
	structuredAPI.POST("/test",
		middleware.RequirePermission(authzService, "policies", "admin"),
		structuredPolicyHandler.TestPolicy)
	structuredAPI.GET("/templates",
		middleware.RequirePermission(authzService, "policies", "admin"),
		structuredPolicyHandler.GetPolicyTemplates)
	structuredAPI.GET("/operators",
		middleware.RequirePermission(authzService, "policies", "admin"),
		structuredPolicyHandler.GetOperators)
	structuredAPI.GET("/attributes",
		middleware.RequirePermission(authzService, "policies", "admin"),
		structuredPolicyHandler.GetAttributes)

	// Authorization metrics routes (admin/manager only)
	api.GET("/authorization/metrics",
		productHandler.GetAuthorizationMetrics)
	api.POST("/authorization/metrics/reset",
		middleware.RequirePermission(authzService, "policies", "admin"),
		productHandler.ResetAuthorizationMetrics)

	// ヘルスチェックエンドポイント
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"message": "Enhanced ABAC Authorization Demo API is running",
			"features": gin.H{
				"rbac":                 true,
				"abac":                 true,
				"age_restrictions":     true,
				"region_restrictions":  true,
				"vip_level_control":    true,
				"time_based_control":   true,
				"policy_templates":     true,
				"audit_logging":        true,
				"dynamic_policies":     true,
				"product_specific_acl": true,
			},
		})
	})

	// ルート情報表示エンドポイント
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":     "Enhanced ABAC Authorization Demo API",
			"version":     "2.1.0",
			"description": "ECアプリケーションでの商品閲覧制御デモ - ABACによる年齢制限・地域制限・VIPレベル制御",
			"features": gin.H{
				"rbac":                 "Role-Based Access Control (Casbin)",
				"abac":                 "Attribute-Based Access Control with age/region/VIP restrictions",
				"age_restrictions":     "Age-based product access control",
				"region_restrictions":  "Geographic access restrictions",
				"vip_level_control":    "VIP level-based premium content access",
				"time_based_control":   "Time-sensitive access restrictions",
				"policy_templates":     "Template-based policy creation",
				"audit_logging":        "Comprehensive audit trail",
				"dynamic_policies":     "Runtime policy management",
				"product_specific_acl": "Product-specific access control policies",
			},
			"endpoints": gin.H{
				"health": "GET /health",
				"login":  "POST /api/auth/login",
				"products": gin.H{
					"list":         "GET /api/products",
					"get":          "GET /api/products/:id",
					"create":       "POST /api/products",
					"update":       "PUT /api/products/:id",
					"delete":       "DELETE /api/products/:id",
					"set_policy":   "POST /api/products/:id/policy",
					"get_policy":   "GET /api/products/:id/policy",
					"check_access": "GET /api/products/:id/access",
				},
				"casbin_policies": gin.H{
					"create":      "POST /api/casbin/policies",
					"assign_role": "POST /api/casbin/roles/assign",
					"audit_log":   "GET /api/casbin/audit-log",
				},
				"structured_policies": gin.H{
					"create_product_policy": "POST /api/structured-policy/products/:id",
					"get_product_policy":    "GET /api/structured-policy/products/:id",
					"test_policy":           "POST /api/structured-policy/test",
					"templates":             "GET /api/structured-policy/templates",
					"operators":             "GET /api/structured-policy/operators",
					"attributes":            "GET /api/structured-policy/attributes",
				},
				"authorization": gin.H{
					"metrics":       "GET /api/authorization/metrics",
					"reset_metrics": "POST /api/authorization/metrics/reset",
				},
			},
			"abac_examples": gin.H{
				"age_restriction": gin.H{
					"description": "18歳以上の商品アクセス制御",
					"policy":      "r.sub.Age >= 18",
					"example":     "アルコール、タバコ等の年齢制限商品",
				},
				"region_restriction": gin.H{
					"description": "地域限定商品のアクセス制御",
					"policy":      "r.sub.Location in ['JP', 'US']",
					"example":     "特定地域限定販売商品",
				},
				"vip_level": gin.H{
					"description": "VIPレベルによる高級商品アクセス制御",
					"policy":      "r.sub.VIPLevel >= 3",
					"example":     "プレミアム会員限定商品",
				},
				"time_based": gin.H{
					"description": "時間帯による制限（深夜の成人向けコンテンツ等）",
					"policy":      "r.env.Time not in night_hours OR r.sub.Age >= 20",
					"example":     "深夜時間帯での年齢制限強化",
				},
			},
			"test_users": gin.H{
				"alice": gin.H{
					"role":     "admin",
					"age":      30,
					"location": "JP",
					"premium":  true,
					"vipLevel": 5,
					"access":   "全商品・管理機能アクセス可能",
				},
				"bob": gin.H{
					"role":     "operator",
					"age":      25,
					"location": "US",
					"premium":  true,
					"vipLevel": 3,
					"access":   "ほぼ全商品アクセス可能（管理機能除く）",
				},
				"charlie": gin.H{
					"role":     "customer",
					"age":      17,
					"location": "JP",
					"premium":  false,
					"vipLevel": 0,
					"access":   "年齢制限により制限あり",
				},
				"dave": gin.H{
					"role":     "customer",
					"age":      22,
					"location": "EU",
					"premium":  false,
					"vipLevel": 1,
					"access":   "地域制限により一部商品アクセス不可",
				},
			},
			"sample_products": gin.H{
				"general": gin.H{
					"description": "一般商品（制限なし）",
					"access":      "全ユーザー",
				},
				"alcohol": gin.H{
					"description": "アルコール類（20歳以上）",
					"access":      "age >= 20",
				},
				"adult_content": gin.H{
					"description": "成人向けコンテンツ（18歳以上、深夜制限あり）",
					"access":      "age >= 18, time restrictions",
				},
				"luxury": gin.H{
					"description": "高級商品（VIPレベル3以上）",
					"access":      "vipLevel >= 3",
				},
				"regional": gin.H{
					"description": "地域限定商品",
					"access":      "location in allowed regions",
				},
			},
		})
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Enhanced ABAC Authorization Demo API on port %s", port)
	log.Printf("Features: RBAC + ABAC with age/region/VIP/time-based restrictions")
	log.Printf("Access http://localhost:%s for API documentation", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// migrateProductSchema は商品テーブルのマイグレーションを実行
func migrateProductSchema(db *gorm.DB) error {
	return db.AutoMigrate(&model.Product{}, &model.User{})
}

// setupSampleData はサンプル商品データを設定
func setupSampleData(db *gorm.DB, productService service.ProductService) ([]*model.Product, error) {
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
	if err := db.Model(&model.Product{}).Count(&existingCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count existing products: %w", err)
	}

	if existingCount > 0 {
		log.Println("Sample products already exist, skipping creation")
		return nil, nil
	}

	createdProducts := make([]*model.Product, 0, len(sampleProducts))
	for _, productReq := range sampleProducts {
		result, err := productService.CreateProduct(ctx, &productReq, "system")
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
func setupInitialPolicies(store service.CasbinPolicyStore, userService service.UserService, sampleProducts []*model.Product) error {
	ctx := context.Background()

	// RBAC policies
	policies := []service.PolicyRule{
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

	abacPolicies := make([]service.PolicyRule, 0, len(sampleProducts))
	for _, product := range sampleProducts {
		// 仮のABACポリシー
		if product.IsAdult {
			abacPolicies = append(abacPolicies, service.PolicyRule{
				Type:      "abac",
				Condition: "r.sub.Age >= 18",
				Resource:  product.ID,
				Action:    "read",
				Effect:    "allow",
			})
		} else {
			abacPolicies = append(abacPolicies, service.PolicyRule{
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
		user, err := userService.GetUserByUsername(ctx, username)
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

// setupSampleUsers はサンプルユーザーデータを設定
func setupSampleUsers(userService service.UserService) error {
	ctx := context.Background()

	// 既存のユーザー数をチェック
	users, err := userService.ListUsers(ctx, service.UserFilters{})
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
		user, err := userService.CreateUser(ctx, &userReq)
		if err != nil {
			log.Printf("Warning: failed to create sample user %s: %v", userReq.Username, err)
		} else {
			log.Printf("Created sample user: %s (ID: %s)", user.Username, user.ID)
		}
	}

	log.Println("Sample user data setup completed")
	return nil
}
