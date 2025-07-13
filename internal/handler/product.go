package handler

import (
	"net/http"
	"strconv"
	"time"

	"authorization-demo/internal/middleware"
	"authorization-demo/internal/model"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

// ProductHandler は商品のHTTPハンドラー
type ProductHandler struct {
	productService service.ProductService
	authService    *service.AuthorizationService
}

// NewProductHandler は新しい商品ハンドラーを作成
func NewProductHandler(productService service.ProductService, authService *service.AuthorizationService) *ProductHandler {
	return &ProductHandler{
		productService: productService,
		authService:    authService,
	}
}

// GetProducts は商品一覧を取得（ユーザーがアクセス可能な商品のみ）
func (h *ProductHandler) GetProducts(c *gin.Context) {
	// コンテキストからユーザー情報を取得
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	// フィルタ条件を取得
	filters := service.ProductFilters{
		Category: c.Query("category"),
		Region:   c.Query("region"),
	}

	// ページングパラメータ
	if page := c.Query("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			filters.Page = p
		}
	}
	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			filters.Limit = l
		}
	}

	// 価格フィルタ
	if minPrice := c.Query("min_price"); minPrice != "" {
		if price, err := strconv.ParseFloat(minPrice, 64); err == nil {
			filters.MinPrice = price
		}
	}
	if maxPrice := c.Query("max_price"); maxPrice != "" {
		if price, err := strconv.ParseFloat(maxPrice, 64); err == nil {
			filters.MaxPrice = price
		}
	}

	// 成人向けコンテンツフィルタ
	if onlyAdult := c.Query("only_adult"); onlyAdult == "true" {
		adult := true
		filters.OnlyAdult = &adult
	}

	// ユーザーがアクセス可能な商品を取得
	pagedResponse, err := h.productService.GetProductsForUser(c.Request.Context(), user, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get products",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, model.ProductListResponse{
		Products:   pagedResponse.Products,
		Total:      len(pagedResponse.Products), // 後方互換性のため
		Page:       pagedResponse.Page,
		Limit:      pagedResponse.Limit,
		TotalPages: pagedResponse.TotalPages,
		TotalItems: pagedResponse.TotalItems,
	})
}

// GetProduct は指定された商品を取得
func (h *ProductHandler) GetProduct(c *gin.Context) {
	// ミドルウェアで既にアクセス権限がチェック済み
	// 商品IDを取得
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
		return
	}

	// 商品情報を取得
	product, err := h.productService.GetProduct(c.Request.Context(), productID)
	if err != nil {
		if err.Error() == "product not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get product"})
		}
		return
	}

	c.JSON(http.StatusOK, product)
}

// CreateProduct は新しい商品を作成
func (h *ProductHandler) CreateProduct(c *gin.Context) {
	var req model.ProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// コンテキストからユーザー情報を取得
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	// 商品を作成
	product, err := h.productService.CreateProduct(c.Request.Context(), &req, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create product",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, product)
}

// UpdateProduct は商品を更新
func (h *ProductHandler) UpdateProduct(c *gin.Context) {
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
		return
	}

	var req model.ProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// コンテキストからユーザー情報を取得
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	// 商品を更新
	product, err := h.productService.UpdateProduct(c.Request.Context(), productID, &req, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to update product",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, product)
}

// DeleteProduct は商品を削除
func (h *ProductHandler) DeleteProduct(c *gin.Context) {
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
		return
	}

	// コンテキストからユーザー情報を取得
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	// 商品を削除
	if err := h.productService.DeleteProduct(c.Request.Context(), productID, user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete product",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Product deleted successfully"})
}

// SetProductPolicy は商品固有のポリシーを設定
func (h *ProductHandler) SetProductPolicy(c *gin.Context) {
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
		return
	}

	var policy service.ProductPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid policy body",
			"details": err.Error(),
		})
		return
	}

	// コンテキストからユーザー情報を取得
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	// ポリシーを設定
	if err := h.productService.SetProductPolicy(c.Request.Context(), productID, policy, user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to set product policy",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Product policy set successfully"})
}

// GetProductPolicy は商品のポリシーを取得
func (h *ProductHandler) GetProductPolicy(c *gin.Context) {
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
		return
	}

	// ポリシーを取得
	policy, err := h.productService.GetProductPolicy(c.Request.Context(), productID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get product policy",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// CheckProductAccess は商品アクセス権限をチェック
func (h *ProductHandler) CheckProductAccess(c *gin.Context) {
	productID := c.Param("id")
	action := c.Query("action")

	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
		return
	}
	if action == "" {
		action = "read" // デフォルトアクション
	}

	// コンテキストからユーザー情報を取得
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	// アクセス権限をチェック
	allowed, err := h.productService.CheckProductAccess(c.Request.Context(), user.ID, productID, action)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Access check failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"product_id": productID,
		"action":     action,
		"allowed":    allowed,
		"user_id":    user.ID,
	})
}

// GetAuthorizationMetrics は認可サービスのメトリクス情報を取得
func (h *ProductHandler) GetAuthorizationMetrics(c *gin.Context) {
	// 管理者権限チェック
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	if user.Role != "admin" && user.Role != "manager" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to view metrics"})
		return
	}

	metrics := h.authService.GetMetrics()
	c.JSON(http.StatusOK, gin.H{
		"authorization_metrics": metrics,
		"generated_at":          time.Now(),
	})
}

// ResetAuthorizationMetrics は認可メトリクスをリセット
func (h *ProductHandler) ResetAuthorizationMetrics(c *gin.Context) {
	// 管理者権限チェック
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	if user.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only administrators can reset metrics"})
		return
	}

	h.authService.ResetMetrics()
	c.JSON(http.StatusOK, gin.H{
		"message":    "Authorization metrics reset successfully",
		"reset_time": time.Now(),
	})
}
