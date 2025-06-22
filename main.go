package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"authorization-demo/internal/auth"
	"authorization-demo/internal/handler"
	"authorization-demo/internal/middleware"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database connection
	dbConfig := service.DefaultDatabaseConfig()
	db, err := service.ConnectDatabase(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Perform database migration
	if err := service.MigratePolicyStoreSchema(db); err != nil {
		log.Fatalf("Failed to migrate database schema: %v", err)
	}

	// Initialize services
	authService := auth.NewService()
	productService := service.NewProductService()

	// Choose policy store implementation
	// For development with database:
	policyStore := service.NewDatabasePolicyStore(db)

	// For in-memory (original implementation):
	// policyStore := service.NewInMemoryPolicyStore()

	// 初期ポリシーの設定
	if err := setupInitialPolicies(policyStore); err != nil {
		log.Fatalf("Failed to setup initial policies: %v", err)
	}

	// Initialize authorization service
	authzService, err := service.NewAuthorizationService(policyStore)
	if err != nil {
		log.Fatalf("Failed to initialize authorization service: %v", err)
	}

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService)
	productHandler := handler.NewProductHandler(productService)
	policyHandler := handler.NewPolicyHandler(authzService)

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

	// Product routes
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

	// Policy management routes (admin only)
	api.POST("/policies",
		middleware.RequirePermission(authzService, "policies", "admin"),
		policyHandler.CreatePolicy)
	api.POST("/roles/assign",
		middleware.RequirePermission(authzService, "policies", "admin"),
		policyHandler.AssignRole)
	api.GET("/audit-log",
		middleware.RequirePermission(authzService, "policies", "admin"),
		policyHandler.GetAuditLog)

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
					"create":      "POST /api/policies",
					"assign_role": "POST /api/policies/roles/assign",
					"audit_log":   "GET /api/policies/audit",
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
			// Log the error but continue with other policies
			log.Printf("Warning: Failed to save initial policy (this may be normal if it already exists): %v", err)
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
			// Check if this is a "already exists" error, which is fine for initial setup
			if strings.Contains(err.Error(), "already exists") {
				log.Printf("Info: Role assignment already exists for %s -> %s (this is normal)", role.UserID, role.Role)
			} else {
				return fmt.Errorf("failed to assign initial role: %w", err)
			}
		}
	}

	return nil
}
