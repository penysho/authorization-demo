package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"authorization-demo/internal/auth"
	"authorization-demo/internal/handler"
	"authorization-demo/internal/middleware"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

func main() {
	// 設定の読み込み
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Println("DATABASE_URL not set, using in-memory store")
	}

	// サービスを初期化
	authService := auth.NewService()
	productService := service.NewProductService()

	// 基本の認可サービス（DebugHandler用）
	basicAuthzService, err := service.NewAuthorizationService()
	if err != nil {
		log.Fatalf("Failed to initialize basic authorization service: %v", err)
	}

	// ポリシーストアの初期化（環境に応じて選択）
	var policyStore service.PolicyStore
	if dbURL != "" {
		// データベースベースのポリシーストア
		policyStore = service.NewDatabasePolicyStore()
	} else {
		// 開発環境ではインメモリストアを使用
		policyStore = service.NewInMemoryPolicyStore()

		// 初期データの設定
		if err := setupInitialPolicies(policyStore); err != nil {
			log.Fatalf("Failed to setup initial policies: %v", err)
		}
	}

	// 強化された認可サービスの初期化
	enhancedAuthzService, err := service.NewEnhancedAuthorizationService(policyStore)
	if err != nil {
		log.Fatalf("Failed to initialize enhanced authorization service: %v", err)
	}

	// ハンドラーを初期化
	authHandler := handler.NewAuthHandler(authService)
	productHandler := handler.NewProductHandler(productService)
	debugHandler := handler.NewDebugHandler(basicAuthzService)
	policyHandler := handler.NewPolicyHandler(enhancedAuthzService)

	// Ginエンジンを初期化
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

	// APIルートグループ
	api := r.Group("/api")

	// 認証エンドポイント（認証不要）
	auth := api.Group("/auth")
	{
		auth.POST("/login", authHandler.Login)
	}

	// 商品エンドポイント（認証必要）
	products := api.Group("/products")
	products.Use(middleware.AuthMiddleware(authService))
	{
		// 商品一覧取得（全ユーザーが閲覧可能）
		products.GET("",
			middleware.EnhancedRequirePermission(enhancedAuthzService, "products", "read"),
			productHandler.GetProducts)

		// 商品詳細取得（年齢制限あり - ABACで制御）
		products.GET("/:id",
			middleware.EnhancedRequirePermission(enhancedAuthzService, "products", "read"),
			productHandler.GetProduct)

		// 商品更新（運用者以上）
		products.PUT("/:id",
			middleware.EnhancedRequirePermission(enhancedAuthzService, "products", "write"),
			productHandler.UpdateProduct)

		// 商品削除（管理者のみ）
		products.DELETE("/:id",
			middleware.EnhancedRequirePermission(enhancedAuthzService, "products", "delete"),
			productHandler.DeleteProduct)

		// 商品作成（管理者のみ）
		products.POST("",
			middleware.EnhancedRequirePermission(enhancedAuthzService, "products", "write"),
			productHandler.CreateProduct)
	}

	// ポリシー管理エンドポイント（管理者のみ）
	policies := api.Group("/policies")
	policies.Use(middleware.AuthMiddleware(authService))
	policies.Use(middleware.EnhancedRequirePermission(enhancedAuthzService, "policies", "admin"))
	{
		policies.POST("", policyHandler.CreatePolicy)
		policies.DELETE("/:id", policyHandler.DeletePolicy)
		policies.POST("/roles/assign", policyHandler.AssignRole)
		policies.GET("/audit", policyHandler.GetAuditLog)
		policies.GET("/stats", policyHandler.GetPolicyStats)
		policies.POST("/refresh", policyHandler.RefreshPolicies)
		policies.POST("/templates", policyHandler.CreatePolicyFromTemplate)
		policies.POST("/validate", policyHandler.ValidatePolicy)
		policies.GET("/health", policyHandler.HealthCheck)
	}

	// ヘルスチェックエンドポイント
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"message": "Enhanced Authorization Demo API is running",
			"features": gin.H{
				"rbac":             true,
				"abac":             true,
				"policy_templates": true,
				"audit_logging":    true,
				"dynamic_policies": true,
			},
		})
	})

	// デバッグエンドポイント（認証必要）
	debug := api.Group("/debug")
	debug.Use(middleware.AuthMiddleware(authService))
	{
		debug.GET("/permissions", debugHandler.CheckUserPermissions)
	}

	// ルート情報表示エンドポイント
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Enhanced Authorization Demo API",
			"version": "2.0.0",
			"features": gin.H{
				"rbac":             "Role-Based Access Control",
				"abac":             "Attribute-Based Access Control",
				"policy_templates": "Template-based policy creation",
				"audit_logging":    "Comprehensive audit trail",
				"dynamic_policies": "Runtime policy management",
			},
			"endpoints": gin.H{
				"health": "GET /health",
				"login":  "POST /api/auth/login",
				"products": gin.H{
					"list":   "GET /api/products",
					"get":    "GET /api/products/:id",
					"create": "POST /api/products",
					"update": "PUT /api/products/:id",
					"delete": "DELETE /api/products/:id",
				},
				"policies": gin.H{
					"create":        "POST /api/policies",
					"delete":        "DELETE /api/policies/:id",
					"assign_role":   "POST /api/policies/roles/assign",
					"audit_log":     "GET /api/policies/audit",
					"statistics":    "GET /api/policies/stats",
					"refresh":       "POST /api/policies/refresh",
					"from_template": "POST /api/policies/templates",
					"validate":      "POST /api/policies/validate",
					"health_check":  "GET /api/policies/health",
				},
			},
			"test_users": gin.H{
				"alice": gin.H{
					"role":        "admin",
					"age":         30,
					"permissions": "read, write, delete, policy management",
				},
				"bob": gin.H{
					"role":        "operator",
					"age":         25,
					"permissions": "read, write",
				},
				"charlie": gin.H{
					"role":        "customer",
					"age":         17,
					"permissions": "read (age restricted)",
				},
				"dave": gin.H{
					"role":        "customer",
					"age":         22,
					"permissions": "read",
				},
			},
			"api_examples": gin.H{
				"create_policy": gin.H{
					"method": "POST",
					"url":    "/api/policies",
					"headers": gin.H{
						"Authorization": "Bearer <token>",
						"X-User-ID":     "alice",
					},
					"body": gin.H{
						"type":     "rbac",
						"subject":  "manager",
						"resource": "reports",
						"action":   "read",
					},
				},
				"assign_role": gin.H{
					"method": "POST",
					"url":    "/api/policies/roles/assign",
					"headers": gin.H{
						"Authorization": "Bearer <token>",
						"X-User-ID":     "alice",
					},
					"body": gin.H{
						"user_id": "eve",
						"role":    "manager",
					},
				},
			},
		})
	})

	// サーバー起動
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting enhanced authorization server on :%s", port)
	log.Println("Features enabled:")
	log.Println("  - Role-Based Access Control (RBAC)")
	log.Println("  - Attribute-Based Access Control (ABAC)")
	log.Println("  - Policy Templates")
	log.Println("  - Audit Logging")
	log.Println("  - Dynamic Policy Management")

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// setupInitialPolicies は初期ポリシーを設定
func setupInitialPolicies(store service.PolicyStore) error {
	ctx := context.Background()

	// 初期RBACポリシーの設定
	initialPolicies := []service.PolicyRule{
		{
			Type:      "rbac",
			Subject:   "admin",
			Resource:  "products",
			Action:    "read",
			Effect:    "allow",
			CreatedBy: "system",
		},
		{
			Type:      "rbac",
			Subject:   "admin",
			Resource:  "products",
			Action:    "write",
			Effect:    "allow",
			CreatedBy: "system",
		},
		{
			Type:      "rbac",
			Subject:   "admin",
			Resource:  "products",
			Action:    "delete",
			Effect:    "allow",
			CreatedBy: "system",
		},
		{
			Type:      "rbac",
			Subject:   "admin",
			Resource:  "policies",
			Action:    "admin",
			Effect:    "allow",
			CreatedBy: "system",
		},
		{
			Type:      "rbac",
			Subject:   "operator",
			Resource:  "products",
			Action:    "read",
			Effect:    "allow",
			CreatedBy: "system",
		},
		{
			Type:      "rbac",
			Subject:   "operator",
			Resource:  "products",
			Action:    "write",
			Effect:    "allow",
			CreatedBy: "system",
		},
		{
			Type:      "rbac",
			Subject:   "customer",
			Resource:  "products",
			Action:    "read",
			Effect:    "allow",
			CreatedBy: "system",
		},
	}

	for _, policy := range initialPolicies {
		if err := store.SavePolicy(ctx, policy); err != nil {
			return fmt.Errorf("failed to save initial policy: %w", err)
		}
	}

	// 初期ロール割り当て
	initialRoles := []service.RoleAssignment{
		{UserID: "alice", Role: "admin", CreatedBy: "system"},
		{UserID: "bob", Role: "operator", CreatedBy: "system"},
		{UserID: "charlie", Role: "customer", CreatedBy: "system"},
		{UserID: "dave", Role: "customer", CreatedBy: "system"},
	}

	for _, role := range initialRoles {
		if err := store.AssignRole(ctx, role.UserID, role.Role); err != nil {
			return fmt.Errorf("failed to assign initial role: %w", err)
		}
	}

	return nil
}
