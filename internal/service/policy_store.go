package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// PolicyStore は認可ポリシーの永続化を抽象化するインターフェース
type PolicyStore interface {
	// ポリシーの基本操作
	LoadPolicies(ctx context.Context) ([]PolicyRule, error)
	SavePolicy(ctx context.Context, rule PolicyRule) error
	DeletePolicy(ctx context.Context, rule PolicyRule) error

	// ロールの基本操作
	LoadRoles(ctx context.Context) ([]RoleAssignment, error)
	AssignRole(ctx context.Context, userID, role string) error
	RevokeRole(ctx context.Context, userID, role string) error

	// 監査ログ
	LogPolicyChange(ctx context.Context, change PolicyChange) error
	GetAuditLog(ctx context.Context, from, to time.Time) ([]PolicyChange, error)
}

// PolicyRule はポリシールールを表現
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

// RoleAssignment はユーザーとロールの割り当てを表現
type RoleAssignment struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// PolicyChange は監査ログのエントリを表現
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
type PolicyRuleDB struct {
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

func (PolicyRuleDB) TableName() string {
	return "policy_rules"
}

type RoleAssignmentDB struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    string    `gorm:"not null;index"`
	Role      string    `gorm:"not null;index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	CreatedBy string    `gorm:"not null"`
}

func (RoleAssignmentDB) TableName() string {
	return "role_assignments"
}

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

// DatabasePolicyStore はデータベースベースのポリシーストア実装
type DatabasePolicyStore struct {
	db *gorm.DB
}

// NewDatabasePolicyStore creates a new database-backed policy store
func NewDatabasePolicyStore(db *gorm.DB) *DatabasePolicyStore {
	return &DatabasePolicyStore{db: db}
}

// AutoMigrate performs database migration for policy store tables
func (s *DatabasePolicyStore) AutoMigrate() error {
	return s.db.AutoMigrate(
		&PolicyRuleDB{},
		&RoleAssignmentDB{},
		&PolicyChangeDB{},
	)
}

// Helper functions to convert between models
func (s *DatabasePolicyStore) policyRuleToDB(rule PolicyRule) (*PolicyRuleDB, error) {
	return &PolicyRuleDB{
		ID:        rule.ID,
		Type:      rule.Type,
		Subject:   rule.Subject,
		Resource:  rule.Resource,
		Action:    rule.Action,
		Condition: rule.Condition,
		Effect:    rule.Effect,
		CreatedAt: rule.CreatedAt,
		UpdatedAt: rule.UpdatedAt,
		CreatedBy: rule.CreatedBy,
	}, nil
}

func (s *DatabasePolicyStore) policyRuleFromDB(dbRule PolicyRuleDB) (PolicyRule, error) {
	return PolicyRule{
		ID:        dbRule.ID,
		Type:      dbRule.Type,
		Subject:   dbRule.Subject,
		Resource:  dbRule.Resource,
		Action:    dbRule.Action,
		Condition: dbRule.Condition,
		Effect:    dbRule.Effect,
		CreatedAt: dbRule.CreatedAt,
		UpdatedAt: dbRule.UpdatedAt,
		CreatedBy: dbRule.CreatedBy,
	}, nil
}

func (s *DatabasePolicyStore) roleAssignmentToDB(assignment RoleAssignment) RoleAssignmentDB {
	return RoleAssignmentDB{
		UserID:    assignment.UserID,
		Role:      assignment.Role,
		CreatedAt: assignment.CreatedAt,
		CreatedBy: assignment.CreatedBy,
	}
}

func (s *DatabasePolicyStore) roleAssignmentFromDB(dbAssignment RoleAssignmentDB) RoleAssignment {
	return RoleAssignment{
		UserID:    dbAssignment.UserID,
		Role:      dbAssignment.Role,
		CreatedAt: dbAssignment.CreatedAt,
		CreatedBy: dbAssignment.CreatedBy,
	}
}

func (s *DatabasePolicyStore) policyChangeToDB(change PolicyChange) (*PolicyChangeDB, error) {
	var beforeJSON, afterJSON *string

	if change.Before != nil {
		bytes, err := json.Marshal(change.Before)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal before state: %w", err)
		}
		jsonStr := string(bytes)
		beforeJSON = &jsonStr
	}

	if change.After != nil {
		bytes, err := json.Marshal(change.After)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal after state: %w", err)
		}
		jsonStr := string(bytes)
		afterJSON = &jsonStr
	}

	return &PolicyChangeDB{
		ID:        change.ID,
		Type:      change.Type,
		Before:    beforeJSON,
		After:     afterJSON,
		ChangedBy: change.ChangedBy,
		ChangedAt: change.ChangedAt,
		Reason:    change.Reason,
	}, nil
}

func (s *DatabasePolicyStore) policyChangeFromDB(dbChange PolicyChangeDB) (PolicyChange, error) {
	var before, after interface{}

	if dbChange.Before != nil && *dbChange.Before != "" {
		err := json.Unmarshal([]byte(*dbChange.Before), &before)
		if err != nil {
			return PolicyChange{}, fmt.Errorf("failed to unmarshal before state: %w", err)
		}
	}

	if dbChange.After != nil && *dbChange.After != "" {
		err := json.Unmarshal([]byte(*dbChange.After), &after)
		if err != nil {
			return PolicyChange{}, fmt.Errorf("failed to unmarshal after state: %w", err)
		}
	}

	return PolicyChange{
		ID:        dbChange.ID,
		Type:      dbChange.Type,
		Before:    before,
		After:     after,
		ChangedBy: dbChange.ChangedBy,
		ChangedAt: dbChange.ChangedAt,
		Reason:    dbChange.Reason,
	}, nil
}

// DatabasePolicyStore implementations
func (s *DatabasePolicyStore) LoadPolicies(ctx context.Context) ([]PolicyRule, error) {
	var dbRules []PolicyRuleDB
	if err := s.db.WithContext(ctx).Find(&dbRules).Error; err != nil {
		return nil, fmt.Errorf("failed to load policies from database: %w", err)
	}

	rules := make([]PolicyRule, len(dbRules))
	for i, dbRule := range dbRules {
		rule, err := s.policyRuleFromDB(dbRule)
		if err != nil {
			return nil, fmt.Errorf("failed to convert policy rule from database: %w", err)
		}
		rules[i] = rule
	}

	return rules, nil
}

func (s *DatabasePolicyStore) SavePolicy(ctx context.Context, rule PolicyRule) error {
	dbRule, err := s.policyRuleToDB(rule)
	if err != nil {
		return fmt.Errorf("failed to convert policy rule for database: %w", err)
	}

	// Set timestamps if not already set
	if rule.ID == "" {
		dbRule.ID = "" // Let database generate UUID
		now := time.Now()
		dbRule.CreatedAt = now
		dbRule.UpdatedAt = now
	} else {
		dbRule.UpdatedAt = time.Now()
	}

	// Use ON CONFLICT to handle upsert
	result := s.db.WithContext(ctx).Save(dbRule)
	if result.Error != nil {
		return fmt.Errorf("failed to save policy to database: %w", result.Error)
	}

	return nil
}

func (s *DatabasePolicyStore) DeletePolicy(ctx context.Context, rule PolicyRule) error {
	result := s.db.WithContext(ctx).Where("id = ?", rule.ID).Delete(&PolicyRuleDB{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete policy from database: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("policy not found: %s", rule.ID)
	}

	return nil
}

func (s *DatabasePolicyStore) LoadRoles(ctx context.Context) ([]RoleAssignment, error) {
	var dbAssignments []RoleAssignmentDB
	if err := s.db.WithContext(ctx).Find(&dbAssignments).Error; err != nil {
		return nil, fmt.Errorf("failed to load roles from database: %w", err)
	}

	assignments := make([]RoleAssignment, len(dbAssignments))
	for i, dbAssignment := range dbAssignments {
		assignments[i] = s.roleAssignmentFromDB(dbAssignment)
	}

	return assignments, nil
}

func (s *DatabasePolicyStore) AssignRole(ctx context.Context, userID, role string) error {
	// Check if assignment already exists
	var count int64
	err := s.db.WithContext(ctx).Model(&RoleAssignmentDB{}).
		Where("user_id = ? AND role = ?", userID, role).
		Count(&count).Error

	if err != nil {
		return fmt.Errorf("failed to check existing role assignment: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("role assignment already exists: %s -> %s", userID, role)
	}

	assignment := RoleAssignmentDB{
		UserID:    userID,
		Role:      role,
		CreatedAt: time.Now(),
		CreatedBy: "system", // Could be passed as parameter
	}

	if err := s.db.WithContext(ctx).Create(&assignment).Error; err != nil {
		return fmt.Errorf("failed to assign role in database: %w", err)
	}

	return nil
}

func (s *DatabasePolicyStore) RevokeRole(ctx context.Context, userID, role string) error {
	result := s.db.WithContext(ctx).
		Where("user_id = ? AND role = ?", userID, role).
		Delete(&RoleAssignmentDB{})

	if result.Error != nil {
		return fmt.Errorf("failed to revoke role from database: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("role assignment not found: %s -> %s", userID, role)
	}

	return nil
}

func (s *DatabasePolicyStore) LogPolicyChange(ctx context.Context, change PolicyChange) error {
	dbChange, err := s.policyChangeToDB(change)
	if err != nil {
		return fmt.Errorf("failed to convert policy change for database: %w", err)
	}

	// Set timestamp if not already set
	if change.ChangedAt.IsZero() {
		dbChange.ChangedAt = time.Now()
	}

	if err := s.db.WithContext(ctx).Create(dbChange).Error; err != nil {
		return fmt.Errorf("failed to log policy change to database: %w", err)
	}

	return nil
}

func (s *DatabasePolicyStore) GetAuditLog(ctx context.Context, from, to time.Time) ([]PolicyChange, error) {
	var dbChanges []PolicyChangeDB

	query := s.db.WithContext(ctx).Model(&PolicyChangeDB{})
	if !from.IsZero() {
		query = query.Where("changed_at >= ?", from)
	}
	if !to.IsZero() {
		query = query.Where("changed_at <= ?", to)
	}

	if err := query.Order("changed_at DESC").Find(&dbChanges).Error; err != nil {
		return nil, fmt.Errorf("failed to get audit log from database: %w", err)
	}

	changes := make([]PolicyChange, len(dbChanges))
	for i, dbChange := range dbChanges {
		change, err := s.policyChangeFromDB(dbChange)
		if err != nil {
			return nil, fmt.Errorf("failed to convert policy change from database: %w", err)
		}
		changes[i] = change
	}

	return changes, nil
}
