package model

import (
	"time"
)

// PolicyRule represents a policy rule
type PolicyRule struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "rbac" or "abac"
	Subject   string    `json:"subject"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	Condition string    `json:"condition,omitempty"` // ABAC用
	Effect    string    `json:"effect"`              // "allow" or "deny"
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by"`
}

// RoleAssignment represents user role assignment
type RoleAssignment struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// PolicyChange represents audit log entry for policy changes
type PolicyChange struct {
	ID        string      `json:"id"`
	Type      string      `json:"type"` // "policy_add", "policy_delete", "role_assign", etc.
	Before    interface{} `json:"before,omitempty"`
	After     interface{} `json:"after,omitempty"`
	ChangedBy string      `json:"changed_by"`
	ChangedAt time.Time   `json:"changed_at"`
	Reason    string      `json:"reason,omitempty"`
}

// Database models for GORM
type CasbinPolicyRuleDB struct {
	ID        string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Type      string    `gorm:"not null;index"`
	Subject   string    `gorm:"not null;index"`
	Resource  string    `gorm:"not null;index"`
	Action    string    `gorm:"not null;index"`
	Condition string    `gorm:"type:text"`
	Effect    string    `gorm:"not null;default:'allow'"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	CreatedBy string    `gorm:"not null"`
}

func (CasbinPolicyRuleDB) TableName() string {
	return "casbin_policy_rules"
}

type CasbinRoleAssignmentDB struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    string    `gorm:"not null;index"`
	Role      string    `gorm:"not null;index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	CreatedBy string    `gorm:"not null"`
}

func (CasbinRoleAssignmentDB) TableName() string {
	return "casbin_role_assignments"
}

// PolicyChangeDB is the database model for policy changes
// This is not dependent on Casbin.
type PolicyChangeDB struct {
	ID        string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Type      string    `gorm:"not null;index"`
	Before    *string   `gorm:"type:jsonb"` // JSON storage for before state, nullable
	After     *string   `gorm:"type:jsonb"` // JSON storage for after state, nullable
	ChangedBy string    `gorm:"not null;index"`
	ChangedAt time.Time `gorm:"autoCreateTime;index"`
	Reason    string    `gorm:"type:text"`
}

func (PolicyChangeDB) TableName() string {
	return "policy_changes"
}
