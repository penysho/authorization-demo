package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"authorization-demo/internal/middleware"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

// PolicyAdminHandler は管理画面用のポリシー管理ハンドラー
type PolicyAdminHandler struct {
	policyEngine *service.PolicyEngine
}

// NewPolicyAdminHandler creates a new policy admin handler
func NewPolicyAdminHandler(policyEngine *service.PolicyEngine) *PolicyAdminHandler {
	return &PolicyAdminHandler{
		policyEngine: policyEngine,
	}
}

// PolicyConditionRequest は管理画面からのポリシー条件リクエスト
type PolicyConditionRequest struct {
	Name       string                   `json:"name" binding:"required"`
	Type       string                   `json:"type" binding:"required,oneof=simple composite"`
	Conditions []SimpleConditionRequest `json:"conditions,omitempty"`
	LogicalOp  string                   `json:"logical_op,omitempty"`
	Priority   int                      `json:"priority"`
}

// SimpleConditionRequest は単純な条件のリクエスト
type SimpleConditionRequest struct {
	Attribute string      `json:"attribute" binding:"required"`
	Operator  string      `json:"operator" binding:"required"`
	Value     interface{} `json:"value" binding:"required"`
}

// ProductPolicyRequest は商品ポリシーの作成/更新リクエスト
type ProductPolicyRequest struct {
	PolicyType   string                     `json:"policy_type" binding:"required,oneof=allow deny"`
	Conditions   []PolicyConditionRequest   `json:"conditions" binding:"required"`
	Restrictions *PolicyRestrictionsRequest `json:"restrictions,omitempty"`
}

// PolicyRestrictionsRequest は制限事項のリクエスト
type PolicyRestrictionsRequest struct {
	TimeRestrictions   *TimeRestrictionRequest `json:"time_restrictions,omitempty"`
	DeviceRestrictions []string                `json:"device_restrictions,omitempty"`
	IPRestrictions     []string                `json:"ip_restrictions,omitempty"`
}

// TimeRestrictionRequest は時間制限のリクエスト
type TimeRestrictionRequest struct {
	StartTime  string   `json:"start_time" binding:"required"`
	EndTime    string   `json:"end_time" binding:"required"`
	DaysOfWeek []string `json:"days_of_week" binding:"required"`
	Timezone   string   `json:"timezone" binding:"required"`
}

// CreateProductPolicy は商品のポリシーを作成/更新
func (h *PolicyAdminHandler) CreateProductPolicy(c *gin.Context) {
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
		return
	}

	var req ProductPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Get user from context
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	// Convert request to service model
	policy := service.ProductAccessPolicy{
		ProductID:  productID,
		PolicyType: req.PolicyType,
		CreatedBy:  user.ID,
		UpdatedAt:  time.Now(),
	}

	// Convert conditions
	conditions := make([]service.PolicyCondition, len(req.Conditions))
	for i, condReq := range req.Conditions {
		condition := service.PolicyCondition{
			Name:      condReq.Name,
			Type:      condReq.Type,
			LogicalOp: condReq.LogicalOp,
			Priority:  condReq.Priority,
			Enabled:   true,
		}

		// Convert simple conditions to JSON
		if condReq.Type == "simple" {
			simpleConditions := make([]service.SimpleCondition, len(condReq.Conditions))
			for j, sc := range condReq.Conditions {
				simpleConditions[j] = service.SimpleCondition{
					Attribute: sc.Attribute,
					Operator:  sc.Operator,
					Value:     sc.Value,
				}
			}
			conditionsJSON, err := json.Marshal(simpleConditions)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "Failed to process conditions",
					"details": err.Error(),
				})
				return
			}
			condition.Conditions = conditionsJSON
		}

		conditions[i] = condition
	}
	policy.Conditions = conditions

	// Convert restrictions if present
	if req.Restrictions != nil {
		restrictionsJSON, err := json.Marshal(req.Restrictions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to process restrictions",
				"details": err.Error(),
			})
			return
		}
		policy.Restrictions = restrictionsJSON
	}

	// Create or update policy
	if err := h.policyEngine.CreateProductPolicy(c.Request.Context(), productID, policy, user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create policy",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Policy created successfully",
		"policy": gin.H{
			"product_id":  productID,
			"policy_type": req.PolicyType,
			"conditions":  req.Conditions,
			"created_by":  user.ID,
			"created_at":  time.Now(),
		},
	})
}

// GetProductPolicy は商品のポリシーを取得
func (h *PolicyAdminHandler) GetProductPolicy(c *gin.Context) {
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product ID is required"})
		return
	}

	policy, err := h.policyEngine.GetProductPolicy(c.Request.Context(), productID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get policy",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// TestPolicy は指定されたユーザーとポリシーでアクセス可否をテスト
func (h *PolicyAdminHandler) TestPolicy(c *gin.Context) {
	var req struct {
		UserID    string               `json:"user_id" binding:"required"`
		ProductID string               `json:"product_id" binding:"required"`
		Action    string               `json:"action" binding:"required"`
		Policy    ProductPolicyRequest `json:"policy" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// This would need to be implemented with a test user and temporary policy evaluation
	// For now, return a placeholder response
	c.JSON(http.StatusOK, gin.H{
		"message": "Policy test functionality not yet implemented",
		"request": req,
	})
}

// GetPolicyTemplates は利用可能なポリシーテンプレートを返す
func (h *PolicyAdminHandler) GetPolicyTemplates(c *gin.Context) {
	templates := []gin.H{
		{
			"id":          "age_restriction",
			"name":        "年齢制限",
			"description": "指定した年齢以上のユーザーのみアクセス可能",
			"template": PolicyConditionRequest{
				Name: "年齢制限",
				Type: "simple",
				Conditions: []SimpleConditionRequest{
					{
						Attribute: "age",
						Operator:  ">=",
						Value:     18,
					},
				},
			},
		},
		{
			"id":          "region_restriction",
			"name":        "地域制限",
			"description": "指定した地域のユーザーのみアクセス可能",
			"template": PolicyConditionRequest{
				Name: "地域制限",
				Type: "simple",
				Conditions: []SimpleConditionRequest{
					{
						Attribute: "location",
						Operator:  "in",
						Value:     []string{"JP", "US"},
					},
				},
			},
		},
		{
			"id":          "vip_only",
			"name":        "VIP限定",
			"description": "指定したVIPレベル以上のユーザーのみアクセス可能",
			"template": PolicyConditionRequest{
				Name: "VIP限定",
				Type: "simple",
				Conditions: []SimpleConditionRequest{
					{
						Attribute: "vip_level",
						Operator:  ">=",
						Value:     3,
					},
				},
			},
		},
		{
			"id":          "premium_members",
			"name":        "プレミアム会員限定",
			"description": "プレミアム会員のみアクセス可能",
			"template": PolicyConditionRequest{
				Name: "プレミアム会員限定",
				Type: "simple",
				Conditions: []SimpleConditionRequest{
					{
						Attribute: "premium",
						Operator:  "==",
						Value:     true,
					},
				},
			},
		},
		{
			"id":          "business_hours",
			"name":        "営業時間内のみ",
			"description": "営業時間内のみアクセス可能",
			"template": PolicyRestrictionsRequest{
				TimeRestrictions: &TimeRestrictionRequest{
					StartTime:  "09:00",
					EndTime:    "18:00",
					DaysOfWeek: []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
					Timezone:   "Asia/Tokyo",
				},
			},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": templates,
	})
}

// GetOperators は利用可能な演算子を返す
func (h *PolicyAdminHandler) GetOperators(c *gin.Context) {
	operators := gin.H{
		"numeric": []gin.H{
			{"value": "==", "label": "等しい"},
			{"value": "!=", "label": "等しくない"},
			{"value": ">", "label": "より大きい"},
			{"value": ">=", "label": "以上"},
			{"value": "<", "label": "より小さい"},
			{"value": "<=", "label": "以下"},
		},
		"string": []gin.H{
			{"value": "==", "label": "等しい"},
			{"value": "!=", "label": "等しくない"},
			{"value": "in", "label": "含まれる"},
			{"value": "not_in", "label": "含まれない"},
		},
		"boolean": []gin.H{
			{"value": "==", "label": "等しい"},
			{"value": "!=", "label": "等しくない"},
		},
	}

	c.JSON(http.StatusOK, operators)
}

// GetAttributes は利用可能な属性を返す
func (h *PolicyAdminHandler) GetAttributes(c *gin.Context) {
	attributes := []gin.H{
		{
			"name":        "age",
			"label":       "年齢",
			"type":        "numeric",
			"description": "ユーザーの年齢",
		},
		{
			"name":        "location",
			"label":       "地域",
			"type":        "string",
			"description": "ユーザーの地域コード",
			"values":      []string{"JP", "US", "EU", "KR", "CN"},
		},
		{
			"name":        "vip_level",
			"label":       "VIPレベル",
			"type":        "numeric",
			"description": "ユーザーのVIPレベル（0-5）",
		},
		{
			"name":        "premium",
			"label":       "プレミアム会員",
			"type":        "boolean",
			"description": "プレミアム会員かどうか",
		},
		{
			"name":        "role",
			"label":       "ロール",
			"type":        "string",
			"description": "ユーザーのロール",
			"values":      []string{"admin", "operator", "customer"},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"attributes": attributes,
	})
}
