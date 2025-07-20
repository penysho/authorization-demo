package handler

import (
	"context"
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
	userService  service.UserService
}

// NewStructuredPolicyHandler creates a new structured policy handler
func NewStructuredPolicyHandler(policyEngine *service.PolicyEngine, userService service.UserService) *StructuredPolicyHandler {
	return &StructuredPolicyHandler{
		policyEngine: policyEngine,
		userService:  userService,
	}
}

// PolicyConditionRequest は管理画面からのポリシー条件リクエスト（統一版）
type PolicyConditionRequest struct {
	Name        string                    `json:"name" binding:"required"`
	Description string                    `json:"description"`
	Condition   CompositeConditionRequest `json:"condition" binding:"required"`
	Priority    int                       `json:"priority"`
}

// CompositeConditionRequest は複合条件のリクエスト
type CompositeConditionRequest struct {
	LogicalOp  string                   `json:"logical_op,omitempty"` // "AND" or "OR" - optional for single conditions
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

// processCondition processes a policy condition (unified composite approach)
func (h *StructuredPolicyHandler) processCondition(condReq PolicyConditionRequest, resourceType, resourceID string) (model.PolicyCondition, error) {
	condition := model.PolicyCondition{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Name:         condReq.Name,
		Description:  condReq.Description,
		Priority:     condReq.Priority,
		Enabled:      true,
	}

	// Build composite condition
	compositeCondition, err := h.buildCompositeCondition(condReq.Condition)
	if err != nil {
		return condition, fmt.Errorf("failed to build composite condition: %w", err)
	}

	// Marshal to JSON
	conditionJSON, err := json.Marshal(compositeCondition)
	if err != nil {
		return condition, fmt.Errorf("failed to marshal composite condition: %w", err)
	}

	condition.Condition = conditionJSON
	return condition, nil
}

// buildCompositeCondition recursively builds composite conditions
func (h *StructuredPolicyHandler) buildCompositeCondition(compReq CompositeConditionRequest) (model.CompositeCondition, error) {
	if len(compReq.Conditions) == 0 {
		return model.CompositeCondition{}, fmt.Errorf("condition must have at least one sub-condition")
	}

	// Validate logical operator if provided
	if compReq.LogicalOp != "" && compReq.LogicalOp != "AND" && compReq.LogicalOp != "OR" {
		return model.CompositeCondition{}, fmt.Errorf("invalid logical operator: %s (must be 'AND' or 'OR')", compReq.LogicalOp)
	}

	// If single condition and no logical operator, it's a simple composite
	if len(compReq.Conditions) == 1 && compReq.LogicalOp == "" {
		// This is a simple condition wrapped in composite structure
	} else if len(compReq.Conditions) > 1 && compReq.LogicalOp == "" {
		return model.CompositeCondition{}, fmt.Errorf("logical operator is required for multiple conditions")
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

	// Validate operators
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

	// Get test user from database
	testUser, err := h.userService.GetUserByID(c.Request.Context(), req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to get test user",
			"details": err.Error(),
		})
		return
	}

	// Convert policy request to temporary model for testing
	tempPolicy := model.ResourceAccessPolicy{
		ResourceType: req.Policy.ResourceType,
		ResourceID:   req.Policy.ResourceID,
		PolicyType:   req.Policy.PolicyType,
	}

	// Convert conditions
	conditions := make([]model.PolicyCondition, len(req.Policy.Conditions))
	for i, condReq := range req.Policy.Conditions {
		condition, err := h.processCondition(condReq, req.Policy.ResourceType, req.Policy.ResourceID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid policy condition",
				"details": err.Error(),
			})
			return
		}
		conditions[i] = condition
	}
	tempPolicy.Conditions = conditions

	// Test policy evaluation
	result, err := h.evaluateTemporaryPolicy(c.Request.Context(), testUser, req.ResourceType, req.ResourceID, req.Action, &tempPolicy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to evaluate policy",
			"details": err.Error(),
		})
		return
	}

	// Return detailed test result
	c.JSON(http.StatusOK, gin.H{
		"test_result": gin.H{
			"allowed":      result.Allowed,
			"user":         result.UserInfo,
			"policy":       result.PolicyInfo,
			"evaluation":   result.EvaluationDetails,
			"restrictions": result.RestrictionResults,
			"timestamp":    time.Now(),
		},
	})
}

// PolicyTestResult represents the result of a policy test
type PolicyTestResult struct {
	Allowed            bool                   `json:"allowed"`
	UserInfo           map[string]interface{} `json:"user_info"`
	PolicyInfo         map[string]interface{} `json:"policy_info"`
	EvaluationDetails  []ConditionResult      `json:"evaluation_details"`
	RestrictionResults map[string]bool        `json:"restriction_results"`
}

// ConditionResult represents the evaluation result of a single condition
type ConditionResult struct {
	ConditionName string `json:"condition_name"`
	Result        bool   `json:"result"`
	Reason        string `json:"reason"`
}

// evaluateTemporaryPolicy evaluates a policy without persisting it
func (h *StructuredPolicyHandler) evaluateTemporaryPolicy(ctx context.Context, user *model.User, resourceType, resourceID, action string, policy *model.ResourceAccessPolicy) (*PolicyTestResult, error) {
	result := &PolicyTestResult{
		UserInfo: map[string]interface{}{
			"id":        user.ID,
			"username":  user.Username,
			"role":      user.Role,
			"age":       user.Age,
			"location":  user.Location,
			"premium":   user.Premium,
			"vip_level": user.VIPLevel,
		},
		PolicyInfo: map[string]interface{}{
			"resource_type": policy.ResourceType,
			"resource_id":   policy.ResourceID,
			"policy_type":   policy.PolicyType,
			"conditions":    len(policy.Conditions),
		},
		EvaluationDetails:  make([]ConditionResult, 0),
		RestrictionResults: make(map[string]bool),
	}

	// Evaluate each condition
	overallAllowed := false
	for _, condition := range policy.Conditions {
		conditionResult, err := h.evaluateConditionWithDetails(ctx, user, condition)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate condition %s: %w", condition.Name, err)
		}

		result.EvaluationDetails = append(result.EvaluationDetails, *conditionResult)

		if conditionResult.Result {
			overallAllowed = true
			if policy.PolicyType == "allow" {
				break // For allow policies, first matching condition grants access
			}
		}
	}

	// Apply policy type
	if policy.PolicyType == "deny" {
		overallAllowed = !overallAllowed
	}

	// Check restrictions if access is allowed
	if overallAllowed && policy.Restrictions != nil {
		restrictionAllowed, err := h.checkRestrictionsWithDetails(ctx, user, policy.Restrictions)
		if err != nil {
			return nil, fmt.Errorf("failed to check restrictions: %w", err)
		}
		result.RestrictionResults = restrictionAllowed

		// If any restriction fails, deny access
		for _, allowed := range restrictionAllowed {
			if !allowed {
				overallAllowed = false
				break
			}
		}
	}

	result.Allowed = overallAllowed
	return result, nil
}

// evaluateConditionWithDetails evaluates a condition and returns detailed results
func (h *StructuredPolicyHandler) evaluateConditionWithDetails(ctx context.Context, user *model.User, condition model.PolicyCondition) (*ConditionResult, error) {
	// Use the policy engine's evaluation logic
	allowed, err := h.policyEngine.EvaluateCondition(ctx, user, condition)
	if err != nil {
		return nil, err
	}

	reason := "Condition evaluation completed"
	if !allowed {
		reason = "Condition requirements not met"
	}

	return &ConditionResult{
		ConditionName: condition.Name,
		Result:        allowed,
		Reason:        reason,
	}, nil
}

// checkRestrictionsWithDetails checks restrictions and returns detailed results
func (h *StructuredPolicyHandler) checkRestrictionsWithDetails(ctx context.Context, user *model.User, restrictionsData json.RawMessage) (map[string]bool, error) {
	var restrictions model.PolicyRestrictions
	if err := json.Unmarshal(restrictionsData, &restrictions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal restrictions: %w", err)
	}

	results := make(map[string]bool)

	// Check time restrictions
	if restrictions.TimeRestrictions != nil {
		timeAllowed := h.policyEngine.CheckTimeRestriction(restrictions.TimeRestrictions)
		results["time_restrictions"] = timeAllowed
	}

	// Add more restriction checks as needed
	if restrictions.DeviceRestrictions != nil {
		results["device_restrictions"] = true // Placeholder
	}

	if restrictions.IPRestrictions != nil {
		results["ip_restrictions"] = true // Placeholder
	}

	return results, nil
}

// GetPolicyTemplates は利用可能なポリシーテンプレートを返す
func (h *StructuredPolicyHandler) GetPolicyTemplates(c *gin.Context) {
	templates := []gin.H{
		{
			"id":          "age_restriction",
			"name":        "年齢制限",
			"description": "指定した年齢以上のユーザーのみアクセス可能",
			"template": PolicyConditionRequest{
				Name:        "年齢制限",
				Description: "指定した年齢以上のユーザーのみアクセス可能",
				Condition: CompositeConditionRequest{
					Conditions: []NestedConditionRequest{
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
		{
			"id":          "region_restriction",
			"name":        "地域制限",
			"description": "指定した地域のユーザーのみアクセス可能",
			"template": PolicyConditionRequest{
				Name:        "地域制限",
				Description: "指定した地域のユーザーのみアクセス可能",
				Condition: CompositeConditionRequest{
					Conditions: []NestedConditionRequest{
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
			"id":          "vip_only",
			"name":        "VIP限定",
			"description": "指定したVIPレベル以上のユーザーのみアクセス可能",
			"template": PolicyConditionRequest{
				Name:        "VIP限定",
				Description: "指定したVIPレベル以上のユーザーのみアクセス可能",
				Condition: CompositeConditionRequest{
					Conditions: []NestedConditionRequest{
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "vip_level",
								Operator:  ">=",
								Value:     3,
							},
						},
					},
				},
			},
		},
		{
			"id":          "premium_members",
			"name":        "プレミアム会員限定",
			"description": "プレミアム会員のみアクセス可能",
			"template": PolicyConditionRequest{
				Name:        "プレミアム会員限定",
				Description: "プレミアム会員のみアクセス可能",
				Condition: CompositeConditionRequest{
					Conditions: []NestedConditionRequest{
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
			"id":          "business_hours",
			"name":        "営業時間制限",
			"description": "指定した時間帯のみアクセス可能",
			"template": PolicyConditionRequest{
				Name:        "営業時間制限",
				Description: "指定した時間帯のみアクセス可能（時間制限は別途設定）",
				Condition: CompositeConditionRequest{
					Conditions: []NestedConditionRequest{
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "role",
								Operator:  "!=",
								Value:     "guest",
							},
						},
					},
				},
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
				Name:        "高額注文制限",
				Description: "指定金額以上の注文に対する制限",
				Condition: CompositeConditionRequest{
					Conditions: []NestedConditionRequest{
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "amount",
								Operator:  ">",
								Value:     10000,
							},
						},
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
				Name:        "エンタープライズ顧客限定",
				Description: "エンタープライズ顧客のみアクセス可能",
				Condition: CompositeConditionRequest{
					Conditions: []NestedConditionRequest{
						{
							Type: "simple",
							Simple: &SimpleConditionRequest{
								Attribute: "customer_type",
								Operator:  "==",
								Value:     "enterprise",
							},
						},
					},
				},
			},
		},
		{
			"id":          "age_and_premium_composite",
			"name":        "年齢制限とプレミアム会員（AND条件）",
			"description": "18歳以上かつプレミアム会員のユーザーのみアクセス可能",
			"template": PolicyConditionRequest{
				Name:        "年齢制限とプレミアム会員",
				Description: "18歳以上かつプレミアム会員のユーザーのみアクセス可能",
				Condition: CompositeConditionRequest{
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
				Name:        "VIP会員または特別地域",
				Description: "VIPレベル3以上またはJP/USのユーザーがアクセス可能",
				Condition: CompositeConditionRequest{
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
				Name:        "複雑な入れ子条件",
				Description: "プレミアム会員で（VIP3以上またはJP地域）かつ18歳以上",
				Condition: CompositeConditionRequest{
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

// GetAttributes は利用可能な属性を返す（統一されたCompositeCondition用）
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
			"label":       "所在地",
			"type":        "string",
			"description": "ユーザーの所在地（国コード）",
		},
		{
			"name":        "vip_level",
			"label":       "VIPレベル",
			"type":        "numeric",
			"description": "ユーザーのVIPレベル（0-10）",
		},
		{
			"name":        "premium",
			"label":       "プレミアム会員",
			"type":        "boolean",
			"description": "プレミアム会員フラグ",
		},
		{
			"name":        "role",
			"label":       "ロール",
			"type":        "string",
			"description": "ユーザーのロール（admin, user, guest等）",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"user_attributes": attributes,
		"resource_attributes": gin.H{
			"products": []gin.H{
				{"name": "price", "label": "価格", "type": "numeric"},
				{"name": "category", "label": "カテゴリ", "type": "string"},
				{"name": "age_limit", "label": "年齢制限", "type": "numeric"},
				{"name": "region", "label": "地域", "type": "string"},
				{"name": "is_adult", "label": "成人向け", "type": "boolean"},
				{"name": "rating", "label": "レーティング", "type": "string"},
			},
			"orders": []gin.H{
				{"name": "amount", "label": "金額", "type": "numeric"},
				{"name": "status", "label": "ステータス", "type": "string"},
				{"name": "priority", "label": "優先度", "type": "string"},
				{"name": "region", "label": "地域", "type": "string"},
				{"name": "days_old", "label": "経過日数", "type": "numeric"},
			},
			"customers": []gin.H{
				{"name": "customer_type", "label": "顧客タイプ", "type": "string"},
				{"name": "credit_limit", "label": "与信限度額", "type": "numeric"},
				{"name": "total_purchases", "label": "総購入額", "type": "numeric"},
				{"name": "account_status", "label": "アカウント状態", "type": "string"},
				{"name": "payment_terms", "label": "支払条件", "type": "string"},
				{"name": "industry", "label": "業界", "type": "string"},
				{"name": "employee_count", "label": "従業員数", "type": "numeric"},
				{"name": "risk_score", "label": "リスクスコア", "type": "numeric"},
				{"name": "account_age", "label": "アカウント経過日数", "type": "numeric"},
			},
		},
	})
}
