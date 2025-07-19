package model

import (
	"encoding/json"
	"time"
)

// PolicyCondition represents a structured policy condition that can be applied to any resource
type PolicyCondition struct {
	ID           string          `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	ResourceType string          `json:"resource_type" gorm:"type:varchar(50);not null;index"` // e.g., "product", "order", "customer"
	ResourceID   string          `json:"resource_id" gorm:"type:varchar(36);not null;index"`
	Name         string          `json:"name"`
	Type         string          `json:"type"` // "simple" or "composite"
	Conditions   json.RawMessage `json:"conditions" gorm:"type:jsonb"`
	LogicalOp    string          `json:"logical_op,omitempty"` // "AND" or "OR"
	Priority     int             `json:"priority" gorm:"default:0"`
	Enabled      bool            `json:"enabled" gorm:"default:true"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// SimpleCondition represents a single condition
type SimpleCondition struct {
	Attribute string      `json:"attribute"` // e.g., "age", "location", "vip_level"
	Operator  string      `json:"operator"`  // e.g., ">=", "==", "in", "contains"
	Value     interface{} `json:"value"`     // e.g., 18, ["JP", "US"], true
}

// ResourceAccessPolicy represents access policy for any resource type
type ResourceAccessPolicy struct {
	ResourceType string            `json:"resource_type" gorm:"type:varchar(50);primaryKey"`
	ResourceID   string            `json:"resource_id" gorm:"type:varchar(36);primaryKey"`
	PolicyType   string            `json:"policy_type"` // "allow" or "deny"
	Conditions   []PolicyCondition `json:"conditions,omitempty" gorm:"foreignKey:ResourceType,ResourceID;references:ResourceType,ResourceID"`
	Restrictions json.RawMessage   `json:"restrictions" gorm:"type:jsonb"`
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
	StartTime  string   `json:"start_time"`   // "09:00"
	EndTime    string   `json:"end_time"`     // "18:00"
	DaysOfWeek []string `json:"days_of_week"` // ["Mon", "Tue", "Wed", "Thu", "Fri"]
	Timezone   string   `json:"timezone"`     // "Asia/Tokyo"
}

// Common resource types
const (
	ResourceTypeProducts  = "products"
	ResourceTypeOrders    = "orders"
	ResourceTypeCustomers = "customers"
	ResourceTypeInvoices  = "invoices"
	ResourceTypeReports   = "reports"
)
