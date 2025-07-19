package main

import (
	"log"
	"net/http"
	"os"

	"authorization-demo/internal/handler"
	"authorization-demo/internal/infrastructure"
	"authorization-demo/internal/middleware"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database connection
	db, err := infrastructure.ConnectDatabase(infrastructure.DefaultDatabaseConfig())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Perform all database migrations
	if err := infrastructure.MigrateAllSchemas(db); err != nil {
		log.Fatalf("Failed to migrate database schemas: %v", err)
	}

	// Initialize services
	userService := service.NewUserService(db)
	authService := service.NewAuthenticationService(userService)

	casbinPolicyStore := service.NewCasbinDatabasePolicyStore(db)
	structuredPolicyEngine := service.NewPolicyEngine(db)
	authzService, err := service.NewAuthorizationService(casbinPolicyStore, structuredPolicyEngine)
	if err != nil {
		log.Fatalf("Failed to initialize authorization service: %v", err)
	}
	productService := service.NewProductService(db, authzService)

	// Initialize seed data manager and setup sample data
	seedManager := infrastructure.NewSeedDataManager(db, userService, productService)
	if err := seedManager.SeedAll(casbinPolicyStore); err != nil {
		log.Fatalf("Failed to setup seed data: %v", err)
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
		middleware.RequirePermission(authzService, "products", "read"),
		productHandler.GetProducts)
	api.GET("/products/:id",
		middleware.RequirePermission(authzService, "products", "read"),
		productHandler.GetProduct)
	api.PUT("/products/:id",
		middleware.RequirePermission(authzService, "products", "write"),
		productHandler.UpdateProduct)
	api.DELETE("/products/:id",
		middleware.RequirePermission(authzService, "products", "delete"),
		productHandler.DeleteProduct)
	api.POST("/products",
		middleware.RequirePermission(authzService, "products", "write"),
		productHandler.CreateProduct)

	// Casbin policy management routes (admin only)
	casbinAPI := api.Group("/casbin")
	casbinAPI.POST("/policies",
		middleware.RequirePermission(authzService, "policies", "admin"),
		casbinPolicyHandler.CreatePolicy)
	casbinAPI.POST("/roles/assign",
		middleware.RequirePermission(authzService, "policies", "admin"),
		casbinPolicyHandler.AssignRole)
	casbinAPI.GET("/audit-log",
		middleware.RequirePermission(authzService, "policies", "admin"),
		casbinPolicyHandler.GetAuditLog)

	// Structured policy management routes (new generic API)
	structuredAPI := api.Group("/structured-policies")
	structuredAPI.POST("/resources",
		middleware.RequirePermission(authzService, "policies", "admin"),
		structuredPolicyHandler.CreateResourcePolicy)
	structuredAPI.GET("/resources",
		middleware.RequirePermission(authzService, "policies", "admin"),
		structuredPolicyHandler.GetResourcePolicy)
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
