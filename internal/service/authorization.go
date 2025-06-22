package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authorization-demo/internal/model"

	"github.com/casbin/casbin/v2"
)

// AuthorizationService は認可サービス
type AuthorizationService struct {
	policyStore  PolicyStore
	rbacEnforcer *casbin.Enforcer
	abacEnforcer *casbin.Enforcer

	// キャッシュ機能
	policyCache   map[string][]PolicyRule
	roleCacheTime time.Time
	cacheDuration time.Duration
}

// PolicyTemplate はポリシーテンプレートを表現
type PolicyTemplate struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        string            `json:"type"` // "rbac" or "abac"
	Template    string            `json:"template"`
	Variables   map[string]string `json:"variables"`
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(policyStore PolicyStore) (*AuthorizationService, error) {
	// Casbinエンフォーサーの初期化
	rbacEnforcer, err := casbin.NewEnforcer("config/rbac_model.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RBAC enforcer: %w", err)
	}

	abacEnforcer, err := casbin.NewEnforcer("config/abac_model.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ABAC enforcer: %w", err)
	}

	service := &AuthorizationService{
		policyStore:   policyStore,
		rbacEnforcer:  rbacEnforcer,
		abacEnforcer:  abacEnforcer,
		policyCache:   make(map[string][]PolicyRule),
		cacheDuration: 5 * time.Minute, // キャッシュの有効期限
	}

	// 初期ポリシーの読み込み
	if err := service.RefreshPolicies(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load initial policies: %w", err)
	}

	return service, nil
}

// RefreshPolicies はポリシーストアからポリシーを再読み込み
func (s *AuthorizationService) RefreshPolicies(ctx context.Context) error {
	// ポリシーの読み込み
	policies, err := s.policyStore.LoadPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	// Casbinエンフォーサーにポリシーを追加
	s.rbacEnforcer.ClearPolicy()
	s.abacEnforcer.ClearPolicy()

	for _, policy := range policies {
		switch policy.Type {
		case "rbac":
			s.rbacEnforcer.AddPolicy(policy.Subject, policy.Resource, policy.Action)
		case "abac":
			s.abacEnforcer.AddPolicy(policy.Subject, policy.Resource, policy.Action)
		}
	}

	// ロールの読み込み
	roles, err := s.policyStore.LoadRoles(ctx)
	if err != nil {
		return fmt.Errorf("failed to load roles: %w", err)
	}

	// ロール割り当ての設定
	for _, role := range roles {
		s.rbacEnforcer.AddRoleForUser(role.UserID, role.Role)
	}

	// キャッシュの更新
	s.roleCacheTime = time.Now()

	return nil
}

// CheckPermission は総合的な権限チェックを行う
func (s *AuthorizationService) CheckPermission(user *model.User, resource, action string) (bool, error) {
	ctx := context.Background()

	// キャッシュの有効性チェック
	if time.Since(s.roleCacheTime) > s.cacheDuration {
		if err := s.RefreshPolicies(ctx); err != nil {
			return false, fmt.Errorf("failed to refresh policies: %w", err)
		}
	}

	// まずRBACで基本的な権限をチェック
	rbacAllowed, err := s.checkRBACPermission(user, resource, action)
	if err != nil {
		return false, err
	}

	// RBACで許可されていない場合は拒否
	if !rbacAllowed {
		return false, nil
	}

	// 個別リソースの場合はABACでさらに詳細チェック
	if strings.HasPrefix(resource, "product_") {
		abacAllowed, err := s.checkABACPermission(user, resource, action)
		if err != nil {
			return false, err
		}
		return abacAllowed, nil
	}

	return rbacAllowed, nil
}

// checkRBACPermission はRBACによる権限チェック
func (s *AuthorizationService) checkRBACPermission(user *model.User, resource, action string) (bool, error) {
	baseResource := resource
	if strings.HasPrefix(resource, "product_") {
		baseResource = "products"
	}

	allowed, err := s.rbacEnforcer.Enforce(user.Username, baseResource, action)
	if err != nil {
		return false, fmt.Errorf("RBAC permission check failed: %w", err)
	}

	return allowed, nil
}

// checkABACPermission はABACによる権限チェック
func (s *AuthorizationService) checkABACPermission(user *model.User, resource, action string) (bool, error) {
	userRequest := &model.UserRequest{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
		Age:      user.Age,
	}

	allowed, err := s.abacEnforcer.Enforce(userRequest, resource, action)
	if err != nil {
		return false, fmt.Errorf("ABAC permission check failed: %w", err)
	}

	return allowed, nil
}

// AddPolicy は新しいポリシーを追加
func (s *AuthorizationService) AddPolicy(ctx context.Context, policyType, subject, resource, action, createdBy string, attributes map[string]string) error {
	rule := PolicyRule{
		Type:       policyType,
		Subject:    subject,
		Resource:   resource,
		Action:     action,
		Attributes: attributes,
		Effect:     "allow",
		CreatedBy:  createdBy,
	}

	if err := s.policyStore.SavePolicy(ctx, rule); err != nil {
		return fmt.Errorf("failed to save policy: %w", err)
	}

	// 監査ログの記録
	change := PolicyChange{
		Type:      "policy_add",
		After:     rule,
		ChangedBy: createdBy,
		Reason:    "New policy added via API",
	}

	if err := s.policyStore.LogPolicyChange(ctx, change); err != nil {
		// ログ記録の失敗は警告レベルとし、処理は継続
		fmt.Printf("Warning: failed to log policy change: %v\n", err)
	}

	// ポリシーの再読み込み
	return s.RefreshPolicies(ctx)
}

// RemovePolicy はポリシーを削除
func (s *AuthorizationService) RemovePolicy(ctx context.Context, policyID, deletedBy string) error {
	// 削除前のポリシーを取得（監査ログ用）
	policies, err := s.policyStore.LoadPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	var targetPolicy *PolicyRule
	for _, policy := range policies {
		if policy.ID == policyID {
			targetPolicy = &policy
			break
		}
	}

	if targetPolicy == nil {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	if err := s.policyStore.DeletePolicy(ctx, *targetPolicy); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	// 監査ログの記録
	change := PolicyChange{
		Type:      "policy_delete",
		Before:    *targetPolicy,
		ChangedBy: deletedBy,
		Reason:    "Policy deleted via API",
	}

	if err := s.policyStore.LogPolicyChange(ctx, change); err != nil {
		fmt.Printf("Warning: failed to log policy change: %v\n", err)
	}

	// ポリシーの再読み込み
	return s.RefreshPolicies(ctx)
}

// AssignRole はユーザーにロールを割り当て
func (s *AuthorizationService) AssignRole(ctx context.Context, userID, role, assignedBy string) error {
	if err := s.policyStore.AssignRole(ctx, userID, role); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	// 監査ログの記録
	change := PolicyChange{
		Type: "role_assign",
		After: RoleAssignment{
			UserID: userID,
			Role:   role,
		},
		ChangedBy: assignedBy,
		Reason:    "Role assigned via API",
	}

	if err := s.policyStore.LogPolicyChange(ctx, change); err != nil {
		fmt.Printf("Warning: failed to log role assignment: %v\n", err)
	}

	// ポリシーの再読み込み
	return s.RefreshPolicies(ctx)
}

// GetAuditLog は監査ログを取得
func (s *AuthorizationService) GetAuditLog(ctx context.Context, from, to time.Time) ([]PolicyChange, error) {
	return s.policyStore.GetAuditLog(ctx, from, to)
}

// CreatePolicyFromTemplate はテンプレートからポリシーを作成
func (s *AuthorizationService) CreatePolicyFromTemplate(ctx context.Context, template PolicyTemplate, variables map[string]string, createdBy string) error {
	// テンプレート変数の置換
	policyTemplate := template.Template
	for key, value := range variables {
		policyTemplate = strings.ReplaceAll(policyTemplate, fmt.Sprintf("{{%s}}", key), value)
	}

	// ポリシールールの解析（簡単な例）
	parts := strings.Split(policyTemplate, ",")
	if len(parts) < 3 {
		return fmt.Errorf("invalid template format")
	}

	rule := PolicyRule{
		Type:      template.Type,
		Subject:   strings.TrimSpace(parts[0]),
		Resource:  strings.TrimSpace(parts[1]),
		Action:    strings.TrimSpace(parts[2]),
		Effect:    "allow",
		CreatedBy: createdBy,
	}

	return s.AddPolicy(ctx, rule.Type, rule.Subject, rule.Resource, rule.Action, createdBy, nil)
}

// ValidatePolicy はポリシーの妥当性を検証
func (s *AuthorizationService) ValidatePolicy(rule PolicyRule) error {
	if rule.Subject == "" {
		return fmt.Errorf("subject cannot be empty")
	}
	if rule.Resource == "" {
		return fmt.Errorf("resource cannot be empty")
	}
	if rule.Action == "" {
		return fmt.Errorf("action cannot be empty")
	}
	if rule.Type != "rbac" && rule.Type != "abac" {
		return fmt.Errorf("policy type must be 'rbac' or 'abac'")
	}
	if rule.Effect != "allow" && rule.Effect != "deny" {
		return fmt.Errorf("effect must be 'allow' or 'deny'")
	}

	return nil
}

// GetPolicyStats はポリシーの統計情報を取得
func (s *AuthorizationService) GetPolicyStats(ctx context.Context) (map[string]interface{}, error) {
	policies, err := s.policyStore.LoadPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	roles, err := s.policyStore.LoadRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load roles: %w", err)
	}

	stats := map[string]interface{}{
		"total_policies":     len(policies),
		"rbac_policies":      0,
		"abac_policies":      0,
		"total_roles":        len(roles),
		"cache_last_refresh": s.roleCacheTime,
	}

	for _, policy := range policies {
		if policy.Type == "rbac" {
			stats["rbac_policies"] = stats["rbac_policies"].(int) + 1
		} else if policy.Type == "abac" {
			stats["abac_policies"] = stats["abac_policies"].(int) + 1
		}
	}

	return stats, nil
}
