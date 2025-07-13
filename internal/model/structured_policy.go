package model

import (
	"encoding/json"
	"time"
)

// PolicyCondition represents a structured policy condition
type PolicyCondition struct {
	ID         string          `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	ProductID  string          `json:"product_id" gorm:"type:varchar(36);not null;index"`
	Product    *Product        `json:"product,omitempty" gorm:"foreignKey:ProductID;references:ID;constraint:OnDelete:CASCADE"`
	Name       string          `json:"name"`
	Type       string          `json:"type"` // "simple" or "composite"
	Conditions json.RawMessage `json:"conditions" gorm:"type:jsonb"`
	LogicalOp  string          `json:"logical_op,omitempty"` // "AND" or "OR"
	Priority   int             `json:"priority" gorm:"default:0"`
	Enabled    bool            `json:"enabled" gorm:"default:true"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// SimpleCondition represents a single condition
type SimpleCondition struct {
	Attribute string      `json:"attribute"` // e.g., "age", "location", "vip_level"
	Operator  string      `json:"operator"`  // e.g., ">=", "==", "in", "contains"
	Value     interface{} `json:"value"`     // e.g., 18, ["JP", "US"], true
}

// ProductAccessPolicy represents product access policy
type ProductAccessPolicy struct {
	ProductID    string            `json:"product_id" gorm:"type:varchar(36);primaryKey"`
	Product      *Product          `json:"product,omitempty" gorm:"foreignKey:ProductID;references:ID;constraint:OnDelete:CASCADE"`
	PolicyType   string            `json:"policy_type"` // "allow" or "deny"
	Conditions   []PolicyCondition `json:"conditions,omitempty" gorm:"foreignKey:ProductID;references:ProductID"`
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
