package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"authorization-demo/internal/model"

	"gorm.io/gorm"
)

// PolicyEngine は構造化されたポリシーを評価するエンジン
type PolicyEngine struct {
	db *gorm.DB
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(db *gorm.DB) *PolicyEngine {
	return &PolicyEngine{db: db}
}

// PolicyCondition は構造化されたポリシー条件を表現
type PolicyCondition struct {
	ID         string          `json:"id" gorm:"primaryKey"`
	ProductID  string          `json:"product_id" gorm:"index"`
	Name       string          `json:"name"`
	Type       string          `json:"type"` // "simple" or "composite"
	Conditions json.RawMessage `json:"conditions" gorm:"type:jsonb"`
	LogicalOp  string          `json:"logical_op,omitempty"` // "AND" or "OR"
	Priority   int             `json:"priority" gorm:"default:0"`
	Enabled    bool            `json:"enabled" gorm:"default:true"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// SimpleCondition は単一の条件を表現
type SimpleCondition struct {
	Attribute string      `json:"attribute"` // e.g., "age", "location", "vip_level"
	Operator  string      `json:"operator"`  // e.g., ">=", "==", "in", "contains"
	Value     interface{} `json:"value"`     // e.g., 18, ["JP", "US"], true
}

// ProductAccessPolicy は商品のアクセスポリシー
type ProductAccessPolicy struct {
	ProductID    string            `json:"product_id" gorm:"primaryKey"`
	PolicyType   string            `json:"policy_type"` // "allow" or "deny"
	Conditions   []PolicyCondition `json:"-" gorm:"foreignKey:ProductID;references:ProductID"`
	Restrictions json.RawMessage   `json:"restrictions" gorm:"type:jsonb"`
	CreatedBy    string            `json:"created_by"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// PolicyRestrictions は追加の制限事項
type PolicyRestrictions struct {
	TimeRestrictions   *TimeRestriction `json:"time_restrictions,omitempty"`
	DeviceRestrictions []string         `json:"device_restrictions,omitempty"`
	IPRestrictions     []string         `json:"ip_restrictions,omitempty"`
}

// TimeRestriction は時間帯制限
type TimeRestriction struct {
	StartTime  string   `json:"start_time"`   // "09:00"
	EndTime    string   `json:"end_time"`     // "18:00"
	DaysOfWeek []string `json:"days_of_week"` // ["Mon", "Tue", "Wed", "Thu", "Fri"]
	Timezone   string   `json:"timezone"`     // "Asia/Tokyo"
}

// EvaluateProductAccess は商品へのアクセス可否を評価
func (pe *PolicyEngine) EvaluateProductAccess(ctx context.Context, user *model.User, productID string, action string) (bool, error) {
	// Get product access policy
	var policy ProductAccessPolicy
	err := pe.db.WithContext(ctx).
		Where("product_id = ?", productID).
		Preload("Conditions", "enabled = ?", true).
		First(&policy).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// No specific policy found, apply default rules
			return pe.evaluateDefaultAccess(ctx, user, productID, action)
		}
		return false, fmt.Errorf("failed to load product policy: %w", err)
	}

	// Evaluate conditions
	allowed := false
	for _, condition := range policy.Conditions {
		result, err := pe.evaluateCondition(ctx, user, condition)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate condition: %w", err)
		}

		if condition.LogicalOp == "OR" && result {
			allowed = true
			break
		} else if condition.LogicalOp == "AND" && !result {
			allowed = false
			break
		} else if result {
			allowed = true
		}
	}

	// Apply policy type
	if policy.PolicyType == "deny" {
		allowed = !allowed
	}

	// Check additional restrictions
	if allowed && policy.Restrictions != nil {
		allowed, err = pe.checkRestrictions(ctx, user, policy.Restrictions)
		if err != nil {
			return false, fmt.Errorf("failed to check restrictions: %w", err)
		}
	}

	return allowed, nil
}

// evaluateCondition は単一の条件を評価
func (pe *PolicyEngine) evaluateCondition(ctx context.Context, user *model.User, condition PolicyCondition) (bool, error) {
	if condition.Type == "composite" {
		// Handle composite conditions
		var subConditions []PolicyCondition
		if err := json.Unmarshal(condition.Conditions, &subConditions); err != nil {
			return false, fmt.Errorf("failed to unmarshal sub-conditions: %w", err)
		}

		results := make([]bool, len(subConditions))
		for i, subCond := range subConditions {
			result, err := pe.evaluateCondition(ctx, user, subCond)
			if err != nil {
				return false, err
			}
			results[i] = result
		}

		// Apply logical operator
		if condition.LogicalOp == "OR" {
			for _, result := range results {
				if result {
					return true, nil
				}
			}
			return false, nil
		} else { // AND
			for _, result := range results {
				if !result {
					return false, nil
				}
			}
			return true, nil
		}
	}

	// Handle simple conditions
	var simpleConditions []SimpleCondition
	if err := json.Unmarshal(condition.Conditions, &simpleConditions); err != nil {
		return false, fmt.Errorf("failed to unmarshal simple conditions: %w", err)
	}

	for _, cond := range simpleConditions {
		result := pe.evaluateSimpleCondition(user, cond)
		if !result {
			return false, nil
		}
	}

	return true, nil
}

// evaluateSimpleCondition は単純な条件を評価
func (pe *PolicyEngine) evaluateSimpleCondition(user *model.User, condition SimpleCondition) bool {
	switch condition.Attribute {
	case "age":
		return pe.evaluateNumericCondition(float64(user.Age), condition.Operator, condition.Value)
	case "location":
		return pe.evaluateStringCondition(user.Location, condition.Operator, condition.Value)
	case "vip_level":
		return pe.evaluateNumericCondition(float64(user.VIPLevel), condition.Operator, condition.Value)
	case "premium":
		return pe.evaluateBooleanCondition(user.Premium, condition.Operator, condition.Value)
	case "role":
		return pe.evaluateStringCondition(user.Role, condition.Operator, condition.Value)
	default:
		return false
	}
}

// evaluateNumericCondition は数値条件を評価
func (pe *PolicyEngine) evaluateNumericCondition(userValue float64, operator string, conditionValue interface{}) bool {
	value, ok := conditionValue.(float64)
	if !ok {
		// Try to convert from int
		if intVal, ok := conditionValue.(int); ok {
			value = float64(intVal)
		} else {
			return false
		}
	}

	switch operator {
	case ">=":
		return userValue >= value
	case ">":
		return userValue > value
	case "<=":
		return userValue <= value
	case "<":
		return userValue < value
	case "==":
		return userValue == value
	case "!=":
		return userValue != value
	default:
		return false
	}
}

// evaluateStringCondition は文字列条件を評価
func (pe *PolicyEngine) evaluateStringCondition(userValue string, operator string, conditionValue interface{}) bool {
	switch operator {
	case "==":
		if strVal, ok := conditionValue.(string); ok {
			return userValue == strVal
		}
	case "!=":
		if strVal, ok := conditionValue.(string); ok {
			return userValue != strVal
		}
	case "in":
		if arrVal, ok := conditionValue.([]interface{}); ok {
			for _, v := range arrVal {
				if strVal, ok := v.(string); ok && userValue == strVal {
					return true
				}
			}
		}
	case "not_in":
		if arrVal, ok := conditionValue.([]interface{}); ok {
			for _, v := range arrVal {
				if strVal, ok := v.(string); ok && userValue == strVal {
					return false
				}
			}
			return true
		}
	}
	return false
}

// evaluateBooleanCondition はブール条件を評価
func (pe *PolicyEngine) evaluateBooleanCondition(userValue bool, operator string, conditionValue interface{}) bool {
	boolVal, ok := conditionValue.(bool)
	if !ok {
		return false
	}

	switch operator {
	case "==":
		return userValue == boolVal
	case "!=":
		return userValue != boolVal
	default:
		return false
	}
}

// checkRestrictions は追加の制限をチェック
func (pe *PolicyEngine) checkRestrictions(ctx context.Context, user *model.User, restrictionsData json.RawMessage) (bool, error) {
	var restrictions PolicyRestrictions
	if err := json.Unmarshal(restrictionsData, &restrictions); err != nil {
		return false, fmt.Errorf("failed to unmarshal restrictions: %w", err)
	}

	// Check time restrictions
	if restrictions.TimeRestrictions != nil {
		if !pe.checkTimeRestriction(restrictions.TimeRestrictions) {
			return false, nil
		}
	}

	// Additional restriction checks can be added here

	return true, nil
}

// checkTimeRestriction は時間制限をチェック
func (pe *PolicyEngine) checkTimeRestriction(restriction *TimeRestriction) bool {
	// Implementation of time restriction check
	// This is a simplified version - in production, you'd want proper timezone handling
	now := time.Now()

	// Check day of week
	currentDay := now.Format("Mon")
	dayAllowed := false
	for _, day := range restriction.DaysOfWeek {
		if day == currentDay {
			dayAllowed = true
			break
		}
	}

	if !dayAllowed {
		return false
	}

	// Check time range (simplified - ignoring timezone for now)
	currentTime := now.Format("15:04")
	return currentTime >= restriction.StartTime && currentTime <= restriction.EndTime
}

// evaluateDefaultAccess はデフォルトのアクセスルールを評価
func (pe *PolicyEngine) evaluateDefaultAccess(ctx context.Context, user *model.User, productID string, action string) (bool, error) {
	// Default rules when no specific policy is defined
	// For example: all authenticated users can read products
	if action == "read" {
		return true, nil
	}

	// Only admin and operators can write/delete
	if action == "write" || action == "delete" {
		return user.Role == "admin" || user.Role == "operator", nil
	}

	return false, nil
}

// CreateProductPolicy は商品のポリシーを作成
func (pe *PolicyEngine) CreateProductPolicy(ctx context.Context, productID string, policy ProductAccessPolicy, createdBy string) error {
	policy.ProductID = productID
	policy.CreatedBy = createdBy
	policy.UpdatedAt = time.Now()

	return pe.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete existing policy
		if err := tx.Where("product_id = ?", productID).Delete(&ProductAccessPolicy{}).Error; err != nil {
			return err
		}

		// Create new policy
		if err := tx.Create(&policy).Error; err != nil {
			return err
		}

		// Create conditions
		for _, condition := range policy.Conditions {
			condition.ProductID = productID
			if err := tx.Create(&condition).Error; err != nil {
				return err
			}
		}

		return nil
	})
}

// GetProductPolicy は商品のポリシーを取得
func (pe *PolicyEngine) GetProductPolicy(ctx context.Context, productID string) (*ProductAccessPolicy, error) {
	var policy ProductAccessPolicy
	err := pe.db.WithContext(ctx).
		Where("product_id = ?", productID).
		Preload("Conditions").
		First(&policy).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("policy not found for product: %s", productID)
		}
		return nil, fmt.Errorf("failed to get product policy: %w", err)
	}

	return &policy, nil
}
