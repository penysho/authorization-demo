package handler

import (
	"net/http"
	"time"

	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

// PolicyHandler はポリシー管理のためのHTTPハンドラー
type PolicyHandler struct {
	authzService *service.AuthorizationService
}

// NewPolicyHandler creates a new policy handler
func NewPolicyHandler(authzService *service.AuthorizationService) *PolicyHandler {
	return &PolicyHandler{
		authzService: authzService,
	}
}

// CreatePolicyRequest はポリシー作成リクエスト
type CreatePolicyRequest struct {
	Type       string            `json:"type" binding:"required,oneof=rbac abac"`
	Subject    string            `json:"subject" binding:"required"`
	Resource   string            `json:"resource" binding:"required"`
	Action     string            `json:"action" binding:"required"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// AssignRoleRequest はロール割り当てリクエスト
type AssignRoleRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Role   string `json:"role" binding:"required"`
}

// PolicyTemplateRequest はポリシーテンプレートリクエスト
type PolicyTemplateRequest struct {
	TemplateName string            `json:"template_name" binding:"required"`
	Variables    map[string]string `json:"variables" binding:"required"`
}

// CreatePolicy は新しいポリシーを作成
func (h *PolicyHandler) CreatePolicy(c *gin.Context) {
	var req CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// リクエスト元ユーザーの取得（実際の実装では認証ミドルウェアから取得）
	createdBy := c.GetHeader("X-User-ID")
	if createdBy == "" {
		createdBy = "system"
	}

	err := h.authzService.AddPolicy(
		c.Request.Context(),
		req.Type,
		req.Subject,
		req.Resource,
		req.Action,
		createdBy,
		req.Attributes,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create policy",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Policy created successfully",
		"policy": gin.H{
			"type":     req.Type,
			"subject":  req.Subject,
			"resource": req.Resource,
			"action":   req.Action,
		},
	})
}

// DeletePolicy はポリシーを削除
func (h *PolicyHandler) DeletePolicy(c *gin.Context) {
	policyID := c.Param("id")
	if policyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Policy ID is required",
		})
		return
	}

	deletedBy := c.GetHeader("X-User-ID")
	if deletedBy == "" {
		deletedBy = "system"
	}

	err := h.authzService.RemovePolicy(c.Request.Context(), policyID, deletedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete policy",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Policy deleted successfully",
	})
}

// AssignRole はユーザーにロールを割り当て
func (h *PolicyHandler) AssignRole(c *gin.Context) {
	var req AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	assignedBy := c.GetHeader("X-User-ID")
	if assignedBy == "" {
		assignedBy = "system"
	}

	err := h.authzService.AssignRole(c.Request.Context(), req.UserID, req.Role, assignedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to assign role",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Role assigned successfully",
		"assignment": gin.H{
			"user_id": req.UserID,
			"role":    req.Role,
		},
	})
}

// GetAuditLog は監査ログを取得
func (h *PolicyHandler) GetAuditLog(c *gin.Context) {
	// クエリパラメータから期間を取得
	fromStr := c.Query("from")
	toStr := c.Query("to")

	var from, to time.Time
	var err error

	if fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid 'from' date format. Use RFC3339 format.",
			})
			return
		}
	} else {
		// デフォルトで過去24時間
		from = time.Now().Add(-24 * time.Hour)
	}

	if toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid 'to' date format. Use RFC3339 format.",
			})
			return
		}
	} else {
		to = time.Now()
	}

	auditLog, err := h.authzService.GetAuditLog(c.Request.Context(), from, to)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve audit log",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"audit_log": auditLog,
		"period": gin.H{
			"from": from,
			"to":   to,
		},
		"count": len(auditLog),
	})
}

// GetPolicyStats はポリシーの統計情報を取得
func (h *PolicyHandler) GetPolicyStats(c *gin.Context) {
	stats, err := h.authzService.GetPolicyStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve policy statistics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"statistics": stats,
	})
}

// RefreshPolicies はポリシーキャッシュを手動でリフレッシュ
func (h *PolicyHandler) RefreshPolicies(c *gin.Context) {
	err := h.authzService.RefreshPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to refresh policies",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Policies refreshed successfully",
	})
}

// CreatePolicyFromTemplate はテンプレートからポリシーを作成
func (h *PolicyHandler) CreatePolicyFromTemplate(c *gin.Context) {
	var req PolicyTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	createdBy := c.GetHeader("X-User-ID")
	if createdBy == "" {
		createdBy = "system"
	}

	// 事前定義されたテンプレート
	templates := map[string]service.PolicyTemplate{
		"admin_access": {
			Name:        "admin_access",
			Description: "Admin access template",
			Type:        "rbac",
			Template:    "{{role}}, {{resource}}, {{action}}",
			Variables:   map[string]string{"role": "", "resource": "", "action": ""},
		},
		"age_restricted_content": {
			Name:        "age_restricted_content",
			Description: "Age-based content access template",
			Type:        "abac",
			Template:    "r.sub.Age >= {{min_age}}, {{resource}}, read",
			Variables:   map[string]string{"min_age": "", "resource": ""},
		},
	}

	template, exists := templates[req.TemplateName]
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":               "Template not found",
			"available_templates": []string{"admin_access", "age_restricted_content"},
		})
		return
	}

	err := h.authzService.CreatePolicyFromTemplate(
		c.Request.Context(),
		template,
		req.Variables,
		createdBy,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create policy from template",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":   "Policy created from template successfully",
		"template":  req.TemplateName,
		"variables": req.Variables,
	})
}

// ValidatePolicy はポリシーの妥当性を検証
func (h *PolicyHandler) ValidatePolicy(c *gin.Context) {
	var rule service.PolicyRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid policy format",
			"details": err.Error(),
		})
		return
	}

	err := h.authzService.ValidatePolicy(rule)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid":   false,
			"error":   "Policy validation failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "Policy is valid",
	})
}

// HealthCheck はポリシーサービスのヘルスチェック
func (h *PolicyHandler) HealthCheck(c *gin.Context) {
	stats, err := h.authzService.GetPolicyStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unhealthy",
			"error":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "healthy",
		"statistics": stats,
		"timestamp":  time.Now(),
	})
}
