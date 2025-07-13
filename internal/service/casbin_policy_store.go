package service

import (
	"authorization-demo/internal/model"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// CasbinPolicyStore は認可ポリシーの永続化を抽象化するインターフェース
type CasbinPolicyStore interface {
	// ポリシーの基本操作
	LoadPolicies(ctx context.Context) ([]model.PolicyRule, error)
	SavePolicy(ctx context.Context, rule model.PolicyRule) error
	DeletePolicy(ctx context.Context, rule model.PolicyRule) error

	// ロールの基本操作
	LoadRoles(ctx context.Context) ([]model.RoleAssignment, error)
	AssignRole(ctx context.Context, userID, role string) error
	RevokeRole(ctx context.Context, userID, role string) error

	// 監査ログ
	LogPolicyChange(ctx context.Context, change model.PolicyChange) error
	GetAuditLog(ctx context.Context, from, to time.Time) ([]model.PolicyChange, error)
}

// CasbinDatabasePolicyStore はデータベースベースのポリシーストア実装
type CasbinDatabasePolicyStore struct {
	db *gorm.DB
}

// NewCasbinDatabasePolicyStore creates a new database-backed policy store
func NewCasbinDatabasePolicyStore(db *gorm.DB) *CasbinDatabasePolicyStore {
	return &CasbinDatabasePolicyStore{db: db}
}

// Helper functions to convert between models
func (s *CasbinDatabasePolicyStore) policyRuleToDB(rule model.PolicyRule) (*model.CasbinPolicyRuleDB, error) {
	return &model.CasbinPolicyRuleDB{
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

func (s *CasbinDatabasePolicyStore) policyRuleFromDB(dbRule model.CasbinPolicyRuleDB) (model.PolicyRule, error) {
	return model.PolicyRule{
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

func (s *CasbinDatabasePolicyStore) roleAssignmentToDB(assignment model.RoleAssignment) model.CasbinRoleAssignmentDB {
	return model.CasbinRoleAssignmentDB{
		UserID:    assignment.UserID,
		Role:      assignment.Role,
		CreatedAt: assignment.CreatedAt,
		CreatedBy: assignment.CreatedBy,
	}
}

func (s *CasbinDatabasePolicyStore) roleAssignmentFromDB(dbAssignment model.CasbinRoleAssignmentDB) model.RoleAssignment {
	return model.RoleAssignment{
		UserID:    dbAssignment.UserID,
		Role:      dbAssignment.Role,
		CreatedAt: dbAssignment.CreatedAt,
		CreatedBy: dbAssignment.CreatedBy,
	}
}

func (s *CasbinDatabasePolicyStore) policyChangeToDB(change model.PolicyChange) (*model.PolicyChangeDB, error) {
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

	return &model.PolicyChangeDB{
		ID:        change.ID,
		Type:      change.Type,
		Before:    beforeJSON,
		After:     afterJSON,
		ChangedBy: change.ChangedBy,
		ChangedAt: change.ChangedAt,
		Reason:    change.Reason,
	}, nil
}

func (s *CasbinDatabasePolicyStore) policyChangeFromDB(dbChange model.PolicyChangeDB) (model.PolicyChange, error) {
	var before, after interface{}

	if dbChange.Before != nil && *dbChange.Before != "" {
		err := json.Unmarshal([]byte(*dbChange.Before), &before)
		if err != nil {
			return model.PolicyChange{}, fmt.Errorf("failed to unmarshal before state: %w", err)
		}
	}

	if dbChange.After != nil && *dbChange.After != "" {
		err := json.Unmarshal([]byte(*dbChange.After), &after)
		if err != nil {
			return model.PolicyChange{}, fmt.Errorf("failed to unmarshal after state: %w", err)
		}
	}

	return model.PolicyChange{
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
func (s *CasbinDatabasePolicyStore) LoadPolicies(ctx context.Context) ([]model.PolicyRule, error) {
	var dbRules []model.CasbinPolicyRuleDB
	if err := s.db.WithContext(ctx).Find(&dbRules).Error; err != nil {
		return nil, fmt.Errorf("failed to load policies from database: %w", err)
	}

	rules := make([]model.PolicyRule, len(dbRules))
	for i, dbRule := range dbRules {
		rule, err := s.policyRuleFromDB(dbRule)
		if err != nil {
			return nil, fmt.Errorf("failed to convert policy rule from database: %w", err)
		}
		rules[i] = rule
	}

	return rules, nil
}

func (s *CasbinDatabasePolicyStore) SavePolicy(ctx context.Context, rule model.PolicyRule) error {
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

func (s *CasbinDatabasePolicyStore) DeletePolicy(ctx context.Context, rule model.PolicyRule) error {
	result := s.db.WithContext(ctx).Where("id = ?", rule.ID).Delete(&model.CasbinPolicyRuleDB{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete policy from database: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("policy not found: %s", rule.ID)
	}

	return nil
}

func (s *CasbinDatabasePolicyStore) LoadRoles(ctx context.Context) ([]model.RoleAssignment, error) {
	var dbAssignments []model.CasbinRoleAssignmentDB
	if err := s.db.WithContext(ctx).Find(&dbAssignments).Error; err != nil {
		return nil, fmt.Errorf("failed to load roles from database: %w", err)
	}

	assignments := make([]model.RoleAssignment, len(dbAssignments))
	for i, dbAssignment := range dbAssignments {
		assignments[i] = s.roleAssignmentFromDB(dbAssignment)
	}

	return assignments, nil
}

func (s *CasbinDatabasePolicyStore) AssignRole(ctx context.Context, userID, role string) error {
	// Check if assignment already exists
	var count int64
	err := s.db.WithContext(ctx).Model(&model.CasbinRoleAssignmentDB{}).
		Where("user_id = ? AND role = ?", userID, role).
		Count(&count).Error

	if err != nil {
		return fmt.Errorf("failed to check existing role assignment: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("role assignment already exists: %s -> %s", userID, role)
	}

	assignment := model.CasbinRoleAssignmentDB{
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

func (s *CasbinDatabasePolicyStore) RevokeRole(ctx context.Context, userID, role string) error {
	result := s.db.WithContext(ctx).
		Where("user_id = ? AND role = ?", userID, role).
		Delete(&model.CasbinRoleAssignmentDB{})

	if result.Error != nil {
		return fmt.Errorf("failed to revoke role from database: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("role assignment not found: %s -> %s", userID, role)
	}

	return nil
}

func (s *CasbinDatabasePolicyStore) LogPolicyChange(ctx context.Context, change model.PolicyChange) error {
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

func (s *CasbinDatabasePolicyStore) GetAuditLog(ctx context.Context, from, to time.Time) ([]model.PolicyChange, error) {
	var dbChanges []model.PolicyChangeDB

	query := s.db.WithContext(ctx).Model(&model.PolicyChangeDB{})
	if !from.IsZero() {
		query = query.Where("changed_at >= ?", from)
	}
	if !to.IsZero() {
		query = query.Where("changed_at <= ?", to)
	}

	if err := query.Order("changed_at DESC").Find(&dbChanges).Error; err != nil {
		return nil, fmt.Errorf("failed to get audit log from database: %w", err)
	}

	changes := make([]model.PolicyChange, len(dbChanges))
	for i, dbChange := range dbChanges {
		change, err := s.policyChangeFromDB(dbChange)
		if err != nil {
			return nil, fmt.Errorf("failed to convert policy change from database: %w", err)
		}
		changes[i] = change
	}

	return changes, nil
}
