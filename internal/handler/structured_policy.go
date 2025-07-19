package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"authorization-demo/internal/middleware"
	"authorization-demo/internal/model"
	"authorization-demo/internal/service"

	"github.com/gin-gonic/gin"
)

// StructuredPolicyHandler は構造化ポリシーエンジンのための管理画面用ハンドラー
type StructuredPolicyHandler struct {
	policyEngine *service.PolicyEngine
}

// NewStructuredPolicyHandler creates a new structured policy handler
func NewStructuredPolicyHandler(policyEngine *service.PolicyEngine) *StructuredPolicyHandler {
	return &StructuredPolicyHandler{
		policyEngine: policyEngine,
	}
}

// PolicyConditionRequest は管理画面からのポリシー条件リクエスト
type PolicyConditionRequest struct {
	Name       string                   `json:"name" binding:"required"`
	Type       string                   `json:"type" binding:"required,oneof=simple composite"`
	Conditions []SimpleConditionRequest `json:"conditions,omitempty"` // For simple type compatibility
	Priority   int                      `json:"priority"`
	// New field for composite conditions
	CompositeCondition *CompositeConditionRequest `json:"composite_condition,omitempty"`
}

// CompositeConditionRequest は複合条件のリクエスト
type CompositeConditionRequest struct {
	LogicalOp  string                   `json:"logical_op" binding:"required,oneof=AND OR"`
	Conditions []NestedConditionRequest `json:"conditions" binding:"required"`
}

// NestedConditionRequest は入れ子になった条件のリクエスト（simple or composite）
type NestedConditionRequest struct {
	Type      string                     `json:"type" binding:"required,oneof=simple composite"`
	Simple    *SimpleConditionRequest    `json:"simple,omitempty"`
	Composite *CompositeConditionRequest `json:"composite,omitempty"`
}

// SimpleConditionRequest は単純な条件のリクエスト
type SimpleConditionRequest struct {
	Attribute string      `json:"attribute" binding:"required"`
	Operator  string      `json:"operator" binding:"required"`
	Value     interface{} `json:"value" binding:"required"`
}

// ResourcePolicyRequest は汎用リソースポリシーの作成/更新リクエスト
type ResourcePolicyRequest struct {
	ResourceType string                     `json:"resource_type" binding:"required"`
	ResourceID   string                     `json:"resource_id" binding:"required"`
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

// processCondition processes a single policy condition (simple or composite)
func (h *StructuredPolicyHandler) processCondition(condReq PolicyConditionRequest, resourceType, resourceID string) (model.PolicyCondition, error) {
	condition := model.PolicyCondition{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Name:         condReq.Name,
		Type:         condReq.Type,
		Priority:     condReq.Priority,
		Enabled:      true,
	}

	switch condReq.Type {
	case "simple":
		return h.processSimpleCondition(condition, condReq)
	case "composite":
		return h.processCompositeCondition(condition, condReq)
	default:
		return condition, fmt.Errorf("unsupported condition type: %s", condReq.Type)
	}
}

// processSimpleCondition processes simple conditions
func (h *StructuredPolicyHandler) processSimpleCondition(condition model.PolicyCondition, condReq PolicyConditionRequest) (model.PolicyCondition, error) {
	// Support both old format (Conditions array) and new format (CompositeCondition)
	var simpleConditions []model.SimpleCondition

	if len(condReq.Conditions) > 0 {
		// Legacy format support
		simpleConditions = make([]model.SimpleCondition, len(condReq.Conditions))
		for j, sc := range condReq.Conditions {
			if err := h.validateSimpleCondition(sc); err != nil {
				return condition, fmt.Errorf("invalid simple condition at index %d: %w", j, err)
			}
			simpleConditions[j] = model.SimpleCondition{
				Attribute: sc.Attribute,
				Operator:  sc.Operator,
				Value:     sc.Value,
			}
		}
	} else {
		// New format - should not be used for simple conditions
		return condition, fmt.Errorf("simple condition should use 'conditions' array")
	}

	conditionsJSON, err := json.Marshal(simpleConditions)
	if err != nil {
		return condition, fmt.Errorf("failed to marshal simple conditions: %w", err)
	}
	condition.Conditions = conditionsJSON

	return condition, nil
}

// processCompositeCondition processes composite conditions
func (h *StructuredPolicyHandler) processCompositeCondition(condition model.PolicyCondition, condReq PolicyConditionRequest) (model.PolicyCondition, error) {
	if condReq.CompositeCondition == nil {
		return condition, fmt.Errorf("composite condition data is required for composite type")
	}

	compositeCondition, err := h.buildCompositeCondition(*condReq.CompositeCondition)
	if err != nil {
		return condition, fmt.Errorf("failed to build composite condition: %w", err)
	}

	conditionsJSON, err := json.Marshal(compositeCondition)
	if err != nil {
		return condition, fmt.Errorf("failed to marshal composite condition: %w", err)
	}

	condition.Conditions = conditionsJSON
	condition.LogicalOp = condReq.CompositeCondition.LogicalOp

	return condition, nil
}

// buildCompositeCondition recursively builds composite conditions
func (h *StructuredPolicyHandler) buildCompositeCondition(compReq CompositeConditionRequest) (model.CompositeCondition, error) {
	if len(compReq.Conditions) == 0 {
		return model.CompositeCondition{}, fmt.Errorf("composite condition must have at least one sub-condition")
	}

	conditions := make([]model.ConditionDefinition, len(compReq.Conditions))

	for i, nestedReq := range compReq.Conditions {
		switch nestedReq.Type {
		case "simple":
			if nestedReq.Simple == nil {
				return model.CompositeCondition{}, fmt.Errorf("simple condition data is required at index %d", i)
			}

			if err := h.validateSimpleCondition(*nestedReq.Simple); err != nil {
				return model.CompositeCondition{}, fmt.Errorf("invalid simple condition at index %d: %w", i, err)
			}

			conditions[i] = model.ConditionDefinition{
				Type: "simple",
				Simple: &model.SimpleCondition{
					Attribute: nestedReq.Simple.Attribute,
					Operator:  nestedReq.Simple.Operator,
					Value:     nestedReq.Simple.Value,
				},
			}

		case "composite":
			if nestedReq.Composite == nil {
				return model.CompositeCondition{}, fmt.Errorf("composite condition data is required at index %d", i)
			}

			// Recursive call for nested composite conditions
			nestedComposite, err := h.buildCompositeCondition(*nestedReq.Composite)
			if err != nil {
				return model.CompositeCondition{}, fmt.Errorf("failed to build nested composite condition at index %d: %w", i, err)
			}

			conditions[i] = model.ConditionDefinition{
				Type:      "composite",
				Composite: &nestedComposite,
			}

		default:
			return model.CompositeCondition{}, fmt.Errorf("unsupported nested condition type: %s at index %d", nestedReq.Type, i)
		}
	}

	return model.CompositeCondition{
		LogicalOp:  compReq.LogicalOp,
		Conditions: conditions,
	}, nil
}

// validateSimpleCondition validates a simple condition request
func (h *StructuredPolicyHandler) validateSimpleCondition(sc SimpleConditionRequest) error {
	if sc.Attribute == "" {
		return fmt.Errorf("attribute is required")
	}
	if sc.Operator == "" {
		return fmt.Errorf("operator is required")
	}
	if sc.Value == nil {
		return fmt.Errorf("value is required")
	}

	// Add more specific validation as needed
	validOperators := map[string]bool{
		"==": true, "!=": true, ">": true, ">=": true, "<": true, "<=": true,
		"in": true, "not_in": true, "contains": true, "not_contains": true,
	}

	if !validOperators[sc.Operator] {
		return fmt.Errorf("unsupported operator: %s", sc.Operator)
	}

	return nil
}

// CreateResourcePolicy creates/updates a policy for any resource type
func (h *StructuredPolicyHandler) CreateResourcePolicy(c *gin.Context) {
	var req ResourcePolicyRequest
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
	policy := model.ResourceAccessPolicy{
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		PolicyType:   req.PolicyType,
		CreatedBy:    user.ID,
		UpdatedAt:    time.Now(),
	}

	// Convert conditions
	conditions := make([]model.PolicyCondition, len(req.Conditions))
	for i, condReq := range req.Conditions {
		condition, err := h.processCondition(condReq, req.ResourceType, req.ResourceID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid policy condition",
				"details": err.Error(),
			})
			return
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
	if err := h.policyEngine.CreateResourcePolicy(c.Request.Context(), req.ResourceType, req.ResourceID, policy, user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create policy",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Policy created successfully",
		"policy": gin.H{
			"resource_type": req.ResourceType,
			"resource_id":   req.ResourceID,
			"policy_type":   req.PolicyType,
			"conditions":    req.Conditions,
			"created_by":    user.ID,
			"created_at":    time.Now(),
		},
	})
}

// GetResourcePolicy gets a policy for any resource type
func (h *StructuredPolicyHandler) GetResourcePolicy(c *gin.Context) {
	resourceType := c.Query("resource_type")
	resourceID := c.Query("resource_id")

	if resourceType == "" || resourceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource_type and resource_id are required"})
		return
	}

	policy, err := h.policyEngine.GetResourcePolicy(c.Request.Context(), resourceType, resourceID)
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
func (h *StructuredPolicyHandler) TestPolicy(c *gin.Context) {
	var req struct {
		UserID       string                `json:"user_id" binding:"required"`
		ResourceType string                `json:"resource_type" binding:"required"`
		ResourceID   string                `json:"resource_id" binding:"required"`
		Action       string                `json:"action" binding:"required"`
		Policy       ResourcePolicyRequest `json:"policy" binding:"required"`
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
func (h *StructuredPolicyHandler) GetPolicyTemplates(c *gin.Context) {
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
			"name":        "営業時間制限",
			"description": "指定した時間帯のみアクセス可能",
			"template": PolicyConditionRequest{
				Name:       "営業時間制限",
				Type:       "simple",
				Conditions: []SimpleConditionRequest{}, // 時間制限は別の方法で設定
			},
			"restrictions": PolicyRestrictionsRequest{
				TimeRestrictions: &TimeRestrictionRequest{
					StartTime:  "09:00",
					EndTime:    "18:00",
					DaysOfWeek: []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
					Timezone:   "Asia/Tokyo",
				},
			},
		},
		{
			"id":            "high_value_order",
			"name":          "高額注文制限",
			"description":   "指定金額以上の注文に対する制限",
			"resource_type": "orders",
			"template": PolicyConditionRequest{
				Name: "高額注文制限",
				Type: "simple",
				Conditions: []SimpleConditionRequest{
					{
						Attribute: "amount",
						Operator:  ">",
						Value:     10000,
					},
				},
			},
		},
		{
			"id":            "enterprise_customer",
			"name":          "エンタープライズ顧客限定",
			"description":   "エンタープライズ顧客のみアクセス可能",
			"resource_type": "customers",
			"template": PolicyConditionRequest{
				Name: "エンタープライズ顧客限定",
				Type: "simple",
				Conditions: []SimpleConditionRequest{
					{
						Attribute: "customer_type",
						Operator:  "==",
						Value:     "enterprise",
					},
				},
			},
		},
		{
			"id":          "age_and_premium_composite",
			"name":        "年齢制限とプレミアム会員（AND条件）",
			"description": "18歳以上かつプレミアム会員のユーザーのみアクセス可能",
			"template": PolicyConditionRequest{
				Name: "年齢制限とプレミアム会員",
				Type: "composite",
				CompositeCondition: &CompositeConditionRequest{
					LogicalOp: "AND",
					Conditions: []NestedConditionRequest{
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "age",
								Operator:  ">=",
								Value:     18,
							},
						},
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "premium",
								Operator:  "==",
								Value:     true,
							},
						},
					},
				},
			},
		},
		{
			"id":          "vip_or_special_region_composite",
			"name":        "VIP会員または特別地域（OR条件）",
			"description": "VIPレベル3以上またはJP/USのユーザーがアクセス可能",
			"template": PolicyConditionRequest{
				Name: "VIP会員または特別地域",
				Type: "composite",
				CompositeCondition: &CompositeConditionRequest{
					LogicalOp: "OR",
					Conditions: []NestedConditionRequest{
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "vip_level",
								Operator:  ">=",
								Value:     3,
							},
						},
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "location",
								Operator:  "in",
								Value:     []string{"JP", "US"},
							},
						},
					},
				},
			},
		},
		{
			"id":          "complex_nested_composite",
			"name":        "複雑な入れ子条件（複合の複合）",
			"description": "プレミアム会員で（VIP3以上またはJP地域）かつ18歳以上",
			"template": PolicyConditionRequest{
				Name: "複雑な入れ子条件",
				Type: "composite",
				CompositeCondition: &CompositeConditionRequest{
					LogicalOp: "AND",
					Conditions: []NestedConditionRequest{
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "premium",
								Operator:  "==",
								Value:     true,
							},
						},
						{
							Type: "composite",
							Composite: &CompositeConditionRequest{
								LogicalOp: "OR",
								Conditions: []NestedConditionRequest{
									{
										Type: "simple",
										Simple: &SimpleConditionRequest{
											Attribute: "vip_level",
											Operator:  ">=",
											Value:     3,
										},
									},
									{
										Type: "simple",
										Simple: &SimpleConditionRequest{
											Attribute: "location",
											Operator:  "==",
											Value:     "JP",
										},
									},
								},
							},
						},
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "age",
								Operator:  ">=",
								Value:     18,
							},
						},
					},
				},
			},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": templates,
	})
}

// GetOperators は利用可能な演算子を返す
func (h *StructuredPolicyHandler) GetOperators(c *gin.Context) {
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
func (h *StructuredPolicyHandler) GetAttributes(c *gin.Context) {
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
