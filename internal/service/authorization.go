package service

import (
	"fmt"

	"authorization-demo/internal/model"

	"github.com/casbin/casbin/v2"
)

// AuthorizationService は認可サービス
type AuthorizationService struct {
	rbacEnforcer *casbin.Enforcer
	abacEnforcer *casbin.Enforcer
}

// NewAuthorizationService は新しい認可サービスを作成
func NewAuthorizationService() (*AuthorizationService, error) {
	// RBACエンフォーサーを初期化
	rbacEnforcer, err := casbin.NewEnforcer("config/rbac_model.conf", "config/rbac_policy.csv")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RBAC enforcer: %w", err)
	}

	// ABACエンフォーサーを初期化
	abacEnforcer, err := casbin.NewEnforcer("config/abac_model.conf", "config/abac_policy.csv")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ABAC enforcer: %w", err)
	}

	return &AuthorizationService{
		rbacEnforcer: rbacEnforcer,
		abacEnforcer: abacEnforcer,
	}, nil
}

// CheckRBACPermission はRBACによる権限チェックを行う
func (s *AuthorizationService) CheckRBACPermission(user *model.User, resource, action string) (bool, error) {
	allowed, err := s.rbacEnforcer.Enforce(user.Username, resource, action)
	if err != nil {
		return false, fmt.Errorf("RBAC permission check failed: %w", err)
	}
	return allowed, nil
}

// CheckABACPermission はABACによる権限チェックを行う
func (s *AuthorizationService) CheckABACPermission(user *model.User, resource, action string) (bool, error) {
	// ABACではユーザーの属性（年齢）を使って判定
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

// CheckPermission は総合的な権限チェックを行う（RBACとABACの両方）
func (s *AuthorizationService) CheckPermission(user *model.User, resource, action string) (bool, error) {
	fmt.Printf("[DEBUG] CheckPermission: user=%s, resource=%s, action=%s\n", user.Username, resource, action)

	// 個別商品のアクセスの場合、基本的なproductsリソースの権限をチェック
	baseResource := resource
	if len(resource) > 8 && resource[:8] == "product_" {
		baseResource = "products"
		fmt.Printf("[DEBUG] Product access detected, using baseResource=%s\n", baseResource)
	}

	// まずRBACで基本的な権限をチェック
	rbacAllowed, err := s.CheckRBACPermission(user, baseResource, action)
	if err != nil {
		return false, err
	}
	fmt.Printf("[DEBUG] RBAC check: baseResource=%s, allowed=%v\n", baseResource, rbacAllowed)

	// RBACで許可されていない場合は拒否
	if !rbacAllowed {
		fmt.Printf("[DEBUG] RBAC denied, returning false\n")
		return false, nil
	}

	// RBACで許可されている場合、ABACで詳細な属性チェックを行う
	// 商品固有のリソース（product_1, product_2など）の場合のみABACチェック
	if len(resource) > 8 && resource[:8] == "product_" {
		abacAllowed, err := s.CheckABACPermission(user, resource, action)
		if err != nil {
			return false, err
		}
		fmt.Printf("[DEBUG] ABAC check: resource=%s, allowed=%v\n", resource, abacAllowed)
		return abacAllowed, nil
	}

	// 一般的なリソース（products）の場合はRBACの結果をそのまま返す
	fmt.Printf("[DEBUG] Returning RBAC result: %v\n", rbacAllowed)
	return rbacAllowed, nil
}

// GetUserRoles はユーザーのロールを取得
func (s *AuthorizationService) GetUserRoles(username string) ([]string, error) {
	roles, err := s.rbacEnforcer.GetRolesForUser(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	return roles, nil
}

// GetRolePermissions はロールの権限を取得
func (s *AuthorizationService) GetRolePermissions(role string) ([][]string, error) {
	permissions, err := s.rbacEnforcer.GetPermissionsForUser(role)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	return permissions, nil
}
