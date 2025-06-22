package main

import (
	"log"
	"net/http"

	"authorization-demo/internal/auth"
	"authorization-demo/internal/handler"
	"authorization-demo/internal/middleware"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

func main() {
	// サービスを初期化
	authService := auth.NewService()
	productService := service.NewProductService()

	authzService, err := service.NewAuthorizationService()
	if err != nil {
		log.Fatalf("Failed to initialize authorization service: %v", err)
	}

	// ハンドラーを初期化
	authHandler := handler.NewAuthHandler(authService)
	productHandler := handler.NewProductHandler(productService)
	debugHandler := handler.NewDebugHandler(authzService)

	// Ginエンジンを初期化
	r := gin.Default()

	// CORS設定（開発用）
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

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
			middleware.RequirePermission(authzService, "products", "read"),
			productHandler.GetProducts)

		// 商品詳細取得（年齢制限あり - ABACで制御）
		products.GET("/:id",
			middleware.RequirePermission(authzService, "products", "read"),
			productHandler.GetProduct)

		// 商品更新（運用者以上）
		products.PUT("/:id",
			middleware.RequirePermission(authzService, "products", "write"),
			productHandler.UpdateProduct)

		// 商品削除（管理者のみ）
		products.DELETE("/:id",
			middleware.RequirePermission(authzService, "products", "delete"),
			productHandler.DeleteProduct)

		// 商品作成（管理者のみ）
		products.POST("",
			middleware.RequirePermission(authzService, "products", "write"),
			productHandler.CreateProduct)
	}

	// ヘルスチェックエンドポイント
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"message": "Authorization Demo API is running",
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
			"message": "Authorization Demo API",
			"version": "1.0.0",
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
			},
			"test_users": gin.H{
				"alice": gin.H{
					"role":        "admin",
					"age":         30,
					"permissions": "read, write, delete",
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
		})
	})

	// サーバー起動
	log.Println("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
