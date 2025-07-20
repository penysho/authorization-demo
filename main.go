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
	structuredPolicyHandler := handler.NewStructuredPolicyHandler(structuredPolicyEngine, userService)

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
				"rbac": true,
				"abac": true,
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
