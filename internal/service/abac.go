package service

import (
	"context"
	"fmt"
	"strings"

	"authorization-demo/internal/model"

	"github.com/casbin/casbin/v2"
)

// ABACEngine defines the interface for ABAC (Attribute-Based Access Control) engines
type ABACEngine interface {
	// EvaluatePermission evaluates whether a user has permission to perform an action on a resource
	EvaluatePermission(ctx context.Context, user *model.User, resource, action string) (bool, error)

	// GetEngineType returns the type of the ABAC engine for identification
	GetEngineType() string

	// Initialize performs any necessary initialization for the engine
	Initialize(ctx context.Context) error

	// RefreshPolicies refreshes the policies in the engine
	RefreshPolicies(ctx context.Context, policies []PolicyRule) error
}

// CasbinABACEngine implements ABACEngine using Casbin
type CasbinABACEngine struct {
	enforcer *casbin.Enforcer
}

// NewCasbinABACEngine creates a new Casbin-based ABAC engine
func NewCasbinABACEngine(configPath string) (*CasbinABACEngine, error) {
	enforcer, err := casbin.NewEnforcer(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Casbin ABAC enforcer: %w", err)
	}

	// カスタム関数を追加
	enforcer.AddFunction("contains", containsFunc)
	enforcer.AddFunction("stringContains", stringContainsFunc)

	return &CasbinABACEngine{
		enforcer: enforcer,
	}, nil
}

// EvaluatePermission evaluates permission using Casbin ABAC
func (e *CasbinABACEngine) EvaluatePermission(ctx context.Context, user *model.User, resource, action string) (bool, error) {
	userRequest := &model.UserRequest{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
		Age:      user.Age,
		Location: user.Location,
		Premium:  user.Premium,
		VIPLevel: user.VIPLevel,
	}

	allowed, err := e.enforcer.Enforce(userRequest, resource, action)
	if err != nil {
		return false, fmt.Errorf("casbin ABAC permission check failed: %w", err)
	}

	return allowed, nil
}

// GetEngineType returns the engine type
func (e *CasbinABACEngine) GetEngineType() string {
	return "casbin"
}

// Initialize performs initialization for Casbin engine
func (e *CasbinABACEngine) Initialize(ctx context.Context) error {
	// Casbin enforcer is already initialized in constructor
	return nil
}

// RefreshPolicies refreshes policies in Casbin enforcer
func (e *CasbinABACEngine) RefreshPolicies(ctx context.Context, policies []PolicyRule) error {
	e.enforcer.ClearPolicy()

	for _, policy := range policies {
		if policy.Type == "abac" {
			e.enforcer.AddPolicy(policy.Condition, policy.Resource, policy.Action)
		}
	}

	return nil
}

// StructuredPolicyABACEngine implements ABACEngine using the structured policy engine
type StructuredPolicyABACEngine struct {
	policyEngine *PolicyEngine
}

// NewStructuredPolicyABACEngine creates a new structured policy-based ABAC engine
func NewStructuredPolicyABACEngine(policyEngine *PolicyEngine) *StructuredPolicyABACEngine {
	return &StructuredPolicyABACEngine{
		policyEngine: policyEngine,
	}
}

// EvaluatePermission evaluates permission using the structured policy engine
func (e *StructuredPolicyABACEngine) EvaluatePermission(ctx context.Context, user *model.User, resource, action string) (bool, error) {
	if e.policyEngine == nil {
		return false, fmt.Errorf("structured policy engine is not available")
	}

	allowed, err := e.policyEngine.EvaluateProductAccess(ctx, user, resource, action)
	if err != nil {
		return false, fmt.Errorf("structured policy ABAC permission check failed: %w", err)
	}

	return allowed, nil
}

// GetEngineType returns the engine type
func (e *StructuredPolicyABACEngine) GetEngineType() string {
	return "structured"
}

// Initialize performs initialization for structured policy engine
func (e *StructuredPolicyABACEngine) Initialize(ctx context.Context) error {
	// The policy engine should already be initialized
	if e.policyEngine == nil {
		return fmt.Errorf("policy engine is not set")
	}
	return nil
}

// RefreshPolicies refreshes policies in structured policy engine
func (e *StructuredPolicyABACEngine) RefreshPolicies(ctx context.Context, policies []PolicyRule) error {
	// The structured policy engine manages its own policies
	// This method can be used for any necessary policy refresh logic
	return nil
}

// ABACEngineType represents the type of ABAC engine to use
type ABACEngineType string

const (
	ABACEngineTypeCasbin     ABACEngineType = "casbin"
	ABACEngineTypeStructured ABACEngineType = "structured"
)

// カスタム関数: 文字列に部分文字列が含まれているかチェック
func stringContainsFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("stringContains requires exactly 2 arguments")
	}

	str, ok := args[0].(string)
	if !ok {
		return false, fmt.Errorf("first argument must be a string")
	}

	substr, ok := args[1].(string)
	if !ok {
		return false, fmt.Errorf("second argument must be a string")
	}

	return strings.Contains(str, substr), nil
}

// カスタム関数: 配列やカンマ区切り文字列に値が含まれているかチェック
func containsFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("contains requires exactly 2 arguments")
	}

	// 第一引数: 配列またはカンマ区切り文字列
	container := args[0]
	target := args[1]

	// ターゲットを文字列に変換
	targetStr, ok := target.(string)
	if !ok {
		return false, fmt.Errorf("second argument must be a string")
	}

	// コンテナが文字列の場合（カンマ区切り）
	if containerStr, ok := container.(string); ok {
		if containerStr == "" {
			return false, nil
		}
		parts := strings.Split(containerStr, ",")
		for _, part := range parts {
			if strings.TrimSpace(part) == targetStr {
				return true, nil
			}
		}
		return false, nil
	}

	// コンテナが配列の場合
	if containerSlice, ok := container.([]interface{}); ok {
		for _, item := range containerSlice {
			if itemStr, ok := item.(string); ok && itemStr == targetStr {
				return true, nil
			}
		}
		return false, nil
	}

	return false, fmt.Errorf("first argument must be a string or array")
}
