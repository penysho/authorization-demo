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

// EvaluateResourceAccess evaluates access to any resource type
func (pe *PolicyEngine) EvaluateResourceAccess(ctx context.Context, user *model.User, resourceType, resourceID, action string) (bool, error) {
	// Get resource access policy
	var policy model.ResourceAccessPolicy
	err := pe.db.WithContext(ctx).
		Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).
		Preload("Conditions", "enabled = ?", true).
		First(&policy).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return true, nil // Default allow if no policy exists
		}
		return false, fmt.Errorf("failed to load resource policy: %w", err)
	}

	// Evaluate conditions - all conditions are evaluated as a logical OR
	allowed := false
	for _, condition := range policy.Conditions {
		result, err := pe.EvaluateCondition(ctx, user, condition)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate condition: %w", err)
		}

		if result {
			allowed = true
			break // If any condition passes, allow access
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

// EvaluateCondition evaluates a single condition using CompositeCondition structure
func (pe *PolicyEngine) EvaluateCondition(ctx context.Context, user *model.User, condition model.PolicyCondition) (bool, error) {
	// All conditions use CompositeCondition structure
	var compositeCondition model.CompositeCondition
	if err := json.Unmarshal(condition.Condition, &compositeCondition); err != nil {
		return false, fmt.Errorf("failed to unmarshal composite condition: %w", err)
	}

	return pe.evaluateCompositeCondition(ctx, user, condition.ResourceType, condition.ResourceID, compositeCondition)
}

// evaluateCompositeCondition evaluates composite conditions recursively
func (pe *PolicyEngine) evaluateCompositeCondition(ctx context.Context, user *model.User, resourceType, resourceID string, composite model.CompositeCondition) (bool, error) {
	if len(composite.Conditions) == 0 {
		return false, fmt.Errorf("composite condition must have at least one condition")
	}

	// Handle single condition (simple case)
	if len(composite.Conditions) == 1 && composite.LogicalOp == "" {
		condDef := composite.Conditions[0]
		if condDef.Type == "simple" && condDef.Simple != nil {
			return pe.evaluateSimpleConditionDirect(user, resourceType, resourceID, ctx, *condDef.Simple), nil
		}
		if condDef.Type == "composite" && condDef.Composite != nil {
			return pe.evaluateCompositeCondition(ctx, user, resourceType, resourceID, *condDef.Composite)
		}
		return false, fmt.Errorf("invalid single condition definition")
	}

	// Handle multiple conditions with logical operator
	if composite.LogicalOp == "" {
		return false, fmt.Errorf("logical operator is required for multiple conditions")
	}

	// Evaluate conditions with early exit optimization
	for _, condDef := range composite.Conditions {
		var result bool
		var err error

		switch condDef.Type {
		case "simple":
			if condDef.Simple == nil {
				return false, fmt.Errorf("simple condition data is missing")
			}
			result = pe.evaluateSimpleConditionDirect(user, resourceType, resourceID, ctx, *condDef.Simple)
		case "composite":
			if condDef.Composite == nil {
				return false, fmt.Errorf("composite condition data is missing")
			}
			result, err = pe.evaluateCompositeCondition(ctx, user, resourceType, resourceID, *condDef.Composite)
			if err != nil {
				return false, fmt.Errorf("failed to evaluate nested composite condition: %w", err)
			}
		default:
			return false, fmt.Errorf("unknown condition type: %s", condDef.Type)
		}

		// Early exit optimization
		if composite.LogicalOp == "OR" && result {
			return true, nil
		}
		if composite.LogicalOp == "AND" && !result {
			return false, nil
		}
	}

	// Final result based on logical operator
	return composite.LogicalOp == "AND", nil
}

// evaluateSimpleConditionDirect evaluates a simple condition directly
func (pe *PolicyEngine) evaluateSimpleConditionDirect(user *model.User, resourceType, resourceID string, ctx context.Context, condition model.SimpleCondition) bool {
	// Load resource data if needed
	resourceData, err := pe.loadResourceData(ctx, resourceType, resourceID)
	if err != nil {
		// If resource loading fails, only evaluate user attributes
		resourceData = nil
	}

	return pe.evaluateSimpleCondition(user, resourceType, resourceData, condition)
}

// loadResourceData loads the resource data based on type
func (pe *PolicyEngine) loadResourceData(ctx context.Context, resourceType, resourceID string) (interface{}, error) {
	switch resourceType {
	case model.ResourceTypeProducts:
		var product model.Product
		if err := pe.db.WithContext(ctx).Where("id = ?", resourceID).First(&product).Error; err != nil {
			return nil, err
		}
		return &product, nil
	case model.ResourceTypeOrders:
		var order model.Order
		if err := pe.db.WithContext(ctx).Where("id = ?", resourceID).First(&order).Error; err != nil {
			return nil, err
		}
		return &order, nil
	case model.ResourceTypeCustomers:
		var customer model.Customer
		if err := pe.db.WithContext(ctx).Where("id = ?", resourceID).First(&customer).Error; err != nil {
			return nil, err
		}
		return &customer, nil
	default:
		return nil, nil // Unknown resource type, only user attributes will be evaluated
	}
}

// evaluateSimpleCondition evaluates a simple condition
func (pe *PolicyEngine) evaluateSimpleCondition(user *model.User, resourceType string, resourceData interface{}, condition model.SimpleCondition) bool {
	// First, try user attributes
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
	}

	// Then, try resource-specific attributes
	switch resourceType {
	case model.ResourceTypeProducts:
		if product, ok := resourceData.(*model.Product); ok {
			return pe.evaluateProductAttribute(product, condition)
		}
	case model.ResourceTypeOrders:
		if order, ok := resourceData.(*model.Order); ok {
			return pe.evaluateOrderAttribute(order, condition)
		}
	case model.ResourceTypeCustomers:
		if customer, ok := resourceData.(*model.Customer); ok {
			return pe.evaluateCustomerAttribute(customer, condition)
		}
	}

	return false
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
	var restrictions model.PolicyRestrictions
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
func (pe *PolicyEngine) checkTimeRestriction(restriction *model.TimeRestriction) bool {
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

// CreateResourcePolicy creates a policy for any resource type
func (pe *PolicyEngine) CreateResourcePolicy(ctx context.Context, resourceType, resourceID string, policy model.ResourceAccessPolicy, createdBy string) error {
	policy.ResourceType = resourceType
	policy.ResourceID = resourceID
	policy.CreatedBy = createdBy
	policy.UpdatedAt = time.Now()

	// Validate policy before creation
	if err := pe.validateResourcePolicy(&policy); err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}

	return pe.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete existing conditions first to avoid foreign key constraint violation
		if err := tx.Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).Delete(&model.PolicyCondition{}).Error; err != nil {
			return fmt.Errorf("failed to delete existing conditions: %w", err)
		}

		// Delete existing policy
		if err := tx.Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).Delete(&model.ResourceAccessPolicy{}).Error; err != nil {
			return fmt.Errorf("failed to delete existing policy: %w", err)
		}

		// Create new policy
		if err := tx.Create(&policy).Error; err != nil {
			return fmt.Errorf("failed to create policy: %w", err)
		}

		return nil
	})
}

// validateResourcePolicy validates the entire resource policy
func (pe *PolicyEngine) validateResourcePolicy(policy *model.ResourceAccessPolicy) error {
	// Validate policy type
	if policy.PolicyType != "allow" && policy.PolicyType != "deny" {
		return fmt.Errorf("invalid policy type: %s (must be 'allow' or 'deny')", policy.PolicyType)
	}

	// Validate resource type
	validResourceTypes := []string{
		model.ResourceTypeProducts,
		model.ResourceTypeOrders,
		model.ResourceTypeCustomers,
		model.ResourceTypeInvoices,
		model.ResourceTypeReports,
	}

	valid := false
	for _, validType := range validResourceTypes {
		if policy.ResourceType == validType {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid resource type: %s", policy.ResourceType)
	}

	// Validate conditions
	for _, condition := range policy.Conditions {
		if err := pe.validateCondition(&condition); err != nil {
			return fmt.Errorf("condition validation failed: %w", err)
		}
	}

	return nil
}

// validateCondition validates a single condition
func (pe *PolicyEngine) validateCondition(condition *model.PolicyCondition) error {
	// All conditions use CompositeCondition structure
	var compositeCondition model.CompositeCondition
	if err := json.Unmarshal(condition.Condition, &compositeCondition); err != nil {
		return fmt.Errorf("failed to unmarshal composite condition: %w", err)
	}

	return pe.validateCompositeConditionStructure(compositeCondition)
}

// validateCompositeConditionStructure validates composite condition structure
func (pe *PolicyEngine) validateCompositeConditionStructure(composite model.CompositeCondition) error {
	if len(composite.Conditions) == 0 {
		return fmt.Errorf("composite condition must have at least one sub-condition")
	}

	// Validate logical operator for multiple conditions
	if len(composite.Conditions) > 1 {
		if composite.LogicalOp != "AND" && composite.LogicalOp != "OR" {
			return fmt.Errorf("invalid logical operator: %s (must be 'AND' or 'OR')", composite.LogicalOp)
		}
	} else if composite.LogicalOp != "" {
		// For single conditions, logical operator should be empty
		return fmt.Errorf("logical operator should be empty for single conditions")
	}

	// Recursively validate sub-conditions
	for i, condDef := range composite.Conditions {
		if err := pe.validateConditionDefinition(condDef); err != nil {
			return fmt.Errorf("invalid condition definition at index %d: %w", i, err)
		}
	}

	return nil
}

// validateConditionDefinition validates a condition definition (simple or composite)
func (pe *PolicyEngine) validateConditionDefinition(condDef model.ConditionDefinition) error {
	// Validate condition type
	if condDef.Type != "simple" && condDef.Type != "composite" {
		return fmt.Errorf("invalid condition type: %s (must be 'simple' or 'composite')", condDef.Type)
	}

	switch condDef.Type {
	case "simple":
		if condDef.Simple == nil {
			return fmt.Errorf("simple condition data is required for simple type")
		}
		return pe.validateSimpleConditionItem(*condDef.Simple)
	case "composite":
		if condDef.Composite == nil {
			return fmt.Errorf("composite condition data is required for composite type")
		}
		return pe.validateCompositeConditionStructure(*condDef.Composite)
	default:
		return fmt.Errorf("unknown condition definition type: %s", condDef.Type)
	}
}

// validateSimpleConditionItem validates individual simple condition attributes
func (pe *PolicyEngine) validateSimpleConditionItem(condition model.SimpleCondition) error {
	if condition.Attribute == "" {
		return fmt.Errorf("attribute cannot be empty")
	}

	// Validate operators
	validOperators := []string{">=", ">", "<=", "<", "==", "!=", "in", "not_in", "contains"}
	valid := false
	for _, op := range validOperators {
		if condition.Operator == op {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid operator: %s", condition.Operator)
	}

	if condition.Value == nil {
		return fmt.Errorf("value cannot be nil")
	}

	return nil
}

// GetResourcePolicy gets a policy for any resource type
func (pe *PolicyEngine) GetResourcePolicy(ctx context.Context, resourceType, resourceID string) (*model.ResourceAccessPolicy, error) {
	var policy model.ResourceAccessPolicy
	err := pe.db.WithContext(ctx).
		Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).
		Preload("Conditions").
		First(&policy).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("policy not found for resource: %s/%s", resourceType, resourceID)
		}
		return nil, fmt.Errorf("failed to get resource policy: %w", err)
	}

	return &policy, nil
}

// evaluateProductAttribute evaluates product-specific attributes
func (pe *PolicyEngine) evaluateProductAttribute(product *model.Product, condition model.SimpleCondition) bool {
	switch condition.Attribute {
	case "price":
		return pe.evaluateNumericCondition(product.Price, condition.Operator, condition.Value)
	case "category":
		return pe.evaluateStringCondition(product.Category, condition.Operator, condition.Value)
	case "age_limit":
		return pe.evaluateNumericCondition(float64(product.AgeLimit), condition.Operator, condition.Value)
	case "region":
		return pe.evaluateStringCondition(product.Region, condition.Operator, condition.Value)
	case "is_adult":
		return pe.evaluateBooleanCondition(product.IsAdult, condition.Operator, condition.Value)
	case "rating":
		return pe.evaluateStringCondition(product.Rating, condition.Operator, condition.Value)
	}
	return false
}

// evaluateOrderAttribute evaluates order-specific attributes
func (pe *PolicyEngine) evaluateOrderAttribute(order *model.Order, condition model.SimpleCondition) bool {
	switch condition.Attribute {
	case "amount":
		return pe.evaluateNumericCondition(order.Amount, condition.Operator, condition.Value)
	case "status":
		return pe.evaluateStringCondition(order.Status, condition.Operator, condition.Value)
	case "priority":
		return pe.evaluateStringCondition(order.Priority, condition.Operator, condition.Value)
	case "region":
		return pe.evaluateStringCondition(order.Region, condition.Operator, condition.Value)
	case "days_old":
		daysOld := int(time.Since(order.CreatedAt).Hours() / 24)
		return pe.evaluateNumericCondition(float64(daysOld), condition.Operator, condition.Value)
	}
	return false
}

// evaluateCustomerAttribute evaluates customer-specific attributes
func (pe *PolicyEngine) evaluateCustomerAttribute(customer *model.Customer, condition model.SimpleCondition) bool {
	switch condition.Attribute {
	case "customer_type":
		return pe.evaluateStringCondition(customer.CustomerType, condition.Operator, condition.Value)
	case "credit_limit":
		return pe.evaluateNumericCondition(customer.CreditLimit, condition.Operator, condition.Value)
	case "total_purchases":
		return pe.evaluateNumericCondition(customer.TotalPurchases, condition.Operator, condition.Value)
	case "account_status":
		return pe.evaluateStringCondition(customer.AccountStatus, condition.Operator, condition.Value)
	case "payment_terms":
		return pe.evaluateStringCondition(customer.PaymentTerms, condition.Operator, condition.Value)
	case "industry":
		return pe.evaluateStringCondition(customer.Industry, condition.Operator, condition.Value)
	case "employee_count":
		return pe.evaluateNumericCondition(float64(customer.EmployeeCount), condition.Operator, condition.Value)
	case "risk_score":
		return pe.evaluateNumericCondition(float64(customer.RiskScore), condition.Operator, condition.Value)
	case "account_age":
		accountAge := int(time.Since(customer.CreatedAt).Hours() / 24)
		return pe.evaluateNumericCondition(float64(accountAge), condition.Operator, condition.Value)
	}
	return false
}

// CheckTimeRestriction checks time restriction
func (pe *PolicyEngine) CheckTimeRestriction(restriction *model.TimeRestriction) bool {
	return pe.checkTimeRestriction(restriction)
}
