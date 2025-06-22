package service

import (
	"context"
	"fmt"
	"time"
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
	ID         string            `json:"id"`
	Type       string            `json:"type"` // "rbac" or "abac"
	Subject    string            `json:"subject"`
	Resource   string            `json:"resource"`
	Action     string            `json:"action"`
	Condition  string            `json:"condition,omitempty"`  // ABAC用
	Attributes map[string]string `json:"attributes,omitempty"` // ABAC用
	Effect     string            `json:"effect"`               // "allow" or "deny"
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	CreatedBy  string            `json:"created_by"`
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

// DatabasePolicyStore はデータベースベースのポリシーストア実装
type DatabasePolicyStore struct {
	// 実際の実装では適切なDBクライアントを使用
	// db *sql.DB
}

// DatabasePolicyStore implementations
func (s *DatabasePolicyStore) LoadPolicies(ctx context.Context) ([]PolicyRule, error) {
	// TODO: 実際のデータベースからポリシーを読み込む
	return []PolicyRule{}, nil
}

func (s *DatabasePolicyStore) SavePolicy(ctx context.Context, rule PolicyRule) error {
	// TODO: データベースにポリシーを保存
	return nil
}

func (s *DatabasePolicyStore) DeletePolicy(ctx context.Context, rule PolicyRule) error {
	// TODO: データベースからポリシーを削除
	return nil
}

func (s *DatabasePolicyStore) LoadRoles(ctx context.Context) ([]RoleAssignment, error) {
	// TODO: データベースからロール割り当てを読み込む
	return []RoleAssignment{}, nil
}

func (s *DatabasePolicyStore) AssignRole(ctx context.Context, userID, role string) error {
	// TODO: データベースにロール割り当てを保存
	return nil
}

func (s *DatabasePolicyStore) RevokeRole(ctx context.Context, userID, role string) error {
	// TODO: データベースからロール割り当てを削除
	return nil
}

func (s *DatabasePolicyStore) LogPolicyChange(ctx context.Context, change PolicyChange) error {
	// TODO: データベースに監査ログを保存
	return nil
}

func (s *DatabasePolicyStore) GetAuditLog(ctx context.Context, from, to time.Time) ([]PolicyChange, error) {
	// TODO: データベースから監査ログを取得
	return []PolicyChange{}, nil
}

// InMemoryPolicyStore はメモリベースのポリシーストア実装（開発・テスト用）
type InMemoryPolicyStore struct {
	policies []PolicyRule
	roles    []RoleAssignment
	auditLog []PolicyChange
}

// ファイルベースのポリシーストア（既存のCSVとの互換性用）
type FilePolicyStore struct {
	rbacPath string
	abacPath string
}

// NewDatabasePolicyStore creates a new database-backed policy store
func NewDatabasePolicyStore() *DatabasePolicyStore {
	return &DatabasePolicyStore{}
}

// NewInMemoryPolicyStore creates a new in-memory policy store
func NewInMemoryPolicyStore() *InMemoryPolicyStore {
	return &InMemoryPolicyStore{
		policies: make([]PolicyRule, 0),
		roles:    make([]RoleAssignment, 0),
		auditLog: make([]PolicyChange, 0),
	}
}

// NewFilePolicyStore creates a new file-based policy store
func NewFilePolicyStore(rbacPath, abacPath string) *FilePolicyStore {
	return &FilePolicyStore{
		rbacPath: rbacPath,
		abacPath: abacPath,
	}
}

// InMemoryPolicyStore implementations
func (s *InMemoryPolicyStore) LoadPolicies(ctx context.Context) ([]PolicyRule, error) {
	return s.policies, nil
}

func (s *InMemoryPolicyStore) SavePolicy(ctx context.Context, rule PolicyRule) error {
	rule.UpdatedAt = time.Now()
	if rule.ID == "" {
		rule.ID = fmt.Sprintf("policy_%d", time.Now().UnixNano())
		rule.CreatedAt = time.Now()
	}

	// 既存のポリシーを更新または新規追加
	for i, existing := range s.policies {
		if existing.ID == rule.ID {
			s.policies[i] = rule
			return nil
		}
	}
	s.policies = append(s.policies, rule)
	return nil
}

func (s *InMemoryPolicyStore) DeletePolicy(ctx context.Context, rule PolicyRule) error {
	for i, existing := range s.policies {
		if existing.ID == rule.ID {
			s.policies = append(s.policies[:i], s.policies[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("policy not found: %s", rule.ID)
}

func (s *InMemoryPolicyStore) LoadRoles(ctx context.Context) ([]RoleAssignment, error) {
	return s.roles, nil
}

func (s *InMemoryPolicyStore) AssignRole(ctx context.Context, userID, role string) error {
	assignment := RoleAssignment{
		UserID:    userID,
		Role:      role,
		CreatedAt: time.Now(),
	}
	s.roles = append(s.roles, assignment)
	return nil
}

func (s *InMemoryPolicyStore) RevokeRole(ctx context.Context, userID, role string) error {
	for i, existing := range s.roles {
		if existing.UserID == userID && existing.Role == role {
			s.roles = append(s.roles[:i], s.roles[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("role assignment not found: %s -> %s", userID, role)
}

func (s *InMemoryPolicyStore) LogPolicyChange(ctx context.Context, change PolicyChange) error {
	change.ID = fmt.Sprintf("change_%d", time.Now().UnixNano())
	change.ChangedAt = time.Now()
	s.auditLog = append(s.auditLog, change)
	return nil
}

func (s *InMemoryPolicyStore) GetAuditLog(ctx context.Context, from, to time.Time) ([]PolicyChange, error) {
	var filtered []PolicyChange
	for _, change := range s.auditLog {
		if change.ChangedAt.After(from) && change.ChangedAt.Before(to) {
			filtered = append(filtered, change)
		}
	}
	return filtered, nil
}
