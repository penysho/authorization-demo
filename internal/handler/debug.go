package handler

import (
	"net/http"

	"authorization-demo/internal/middleware"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

// DebugHandler はデバッグ用ハンドラー
type DebugHandler struct {
	authzService *service.AuthorizationService
}

// NewDebugHandler は新しいデバッグハンドラーを作成
func NewDebugHandler(authzService *service.AuthorizationService) *DebugHandler {
	return &DebugHandler{authzService: authzService}
}

// CheckUserPermissions はユーザーの権限チェック結果を表示
func (h *DebugHandler) CheckUserPermissions(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	resource := c.Query("resource")
	action := c.Query("action")

	if resource == "" {
		resource = "products"
	}
	if action == "" {
		action = "read"
	}

	// RBAC権限チェック（individual product は products リソースでチェック）
	rbacResource := resource
	if len(resource) > 8 && resource[:8] == "product_" {
		rbacResource = "products"
	}
	rbacAllowed, rbacErr := h.authzService.CheckRBACPermission(user, rbacResource, action)

	// ABAC権限チェック
	abacAllowed, abacErr := h.authzService.CheckABACPermission(user, resource, action)

	// 総合権限チェック
	totalAllowed, totalErr := h.authzService.CheckPermission(user, resource, action)

	// ユーザーのロール取得
	roles, rolesErr := h.authzService.GetUserRoles(user.Username)

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"username": user.Username,
			"role":     user.Role,
			"age":      user.Age,
		},
		"resource": resource,
		"action":   action,
		"roles":    roles,
		"rbac": gin.H{
			"allowed": rbacAllowed,
			"error":   getErrorString(rbacErr),
		},
		"abac": gin.H{
			"allowed": abacAllowed,
			"error":   getErrorString(abacErr),
		},
		"total": gin.H{
			"allowed": totalAllowed,
			"error":   getErrorString(totalErr),
		},
		"roles_error": getErrorString(rolesErr),
	})
}

func getErrorString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
