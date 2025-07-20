package model

import (
	"encoding/json"
	"time"
)

// PolicyCondition represents a unified policy condition using CompositeCondition structure
type PolicyCondition struct {
	ID           string          `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	ResourceType string          `json:"resource_type" gorm:"type:varchar(50);not null;index"`
	ResourceID   string          `json:"resource_id" gorm:"type:varchar(36);not null;index"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Condition    json.RawMessage `json:"condition" gorm:"type:jsonb"`
	Priority     int             `json:"priority" gorm:"default:0"`
	Enabled      bool            `json:"enabled" gorm:"default:true"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// SimpleCondition represents a single atomic condition
type SimpleCondition struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
}

// CompositeCondition represents a condition with logical operations
type CompositeCondition struct {
	LogicalOp  string                `json:"logical_op,omitempty"`
	Conditions []ConditionDefinition `json:"conditions"`
}

// ConditionDefinition represents either a simple or composite condition
type ConditionDefinition struct {
	Type      string              `json:"type"`
	Simple    *SimpleCondition    `json:"simple,omitempty"`
	Composite *CompositeCondition `json:"composite,omitempty"`
}

// ResourceAccessPolicy represents access policy for any resource type
type ResourceAccessPolicy struct {
	ResourceType string            `json:"resource_type" gorm:"type:varchar(50);primaryKey"`
	ResourceID   string            `json:"resource_id" gorm:"type:varchar(36);primaryKey"`
	PolicyType   string            `json:"policy_type"`
	Conditions   []PolicyCondition `json:"conditions,omitempty" gorm:"foreignKey:ResourceType,ResourceID;references:ResourceType,ResourceID"`
	Restrictions json.RawMessage   `json:"restrictions,omitempty" gorm:"type:jsonb"`
	CreatedBy    string            `json:"created_by"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// PolicyRestrictions represents additional restrictions
type PolicyRestrictions struct {
	TimeRestrictions   *TimeRestriction `json:"time_restrictions,omitempty"`
	DeviceRestrictions []string         `json:"device_restrictions,omitempty"`
	IPRestrictions     []string         `json:"ip_restrictions,omitempty"`
}

// TimeRestriction represents time-based restrictions
type TimeRestriction struct {
	StartTime  string   `json:"start_time"`
	EndTime    string   `json:"end_time"`
	DaysOfWeek []string `json:"days_of_week"`
	Timezone   string   `json:"timezone"`
}

// Resource types
const (
	ResourceTypeProducts  = "products"
	ResourceTypeOrders    = "orders"
	ResourceTypeCustomers = "customers"
	ResourceTypeInvoices  = "invoices"
	ResourceTypeReports   = "reports"
)
