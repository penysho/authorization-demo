package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"authorization-demo/internal/model"

	"github.com/casbin/casbin/v2"
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

// PermissionCache represents a cache entry for permission checks
type PermissionCache struct {
	allowed   bool
	expiresAt time.Time
}

// AuthorizationMetrics represents performance metrics for authorization
type AuthorizationMetrics struct {
	TotalRequests          int64         `json:"total_requests"`
	SuccessfulRequests     int64         `json:"successful_requests"`
	FailedRequests         int64         `json:"failed_requests"`
	CacheHitRate           float64       `json:"cache_hit_rate"`
	CacheHits              int64         `json:"cache_hits"`
	CacheMisses            int64         `json:"cache_misses"`
	AverageResponseTime    time.Duration `json:"average_response_time"`
	BulkRequestCount       int64         `json:"bulk_request_count"`
	PartialEvaluationCount int64         `json:"partial_evaluation_count"`
	LastResetTime          time.Time     `json:"last_reset_time"`
	totalResponseTime      time.Duration `json:"-"`
	mu                     sync.RWMutex  `json:"-"`
}

// AuthorizationService は認可サービス
type AuthorizationService struct {
	policyStore  PolicyStore
	rbacEnforcer *casbin.Enforcer
	abacEnforcer *casbin.Enforcer
	policyEngine *PolicyEngine // 新しい構造化ポリシーエンジン

	// キャッシュ機能
	lastPolicyRefreshTime time.Time     // ポリシー最終更新時刻
	policyRefreshInterval time.Duration // ポリシー再読み込み間隔
	permissionCache       sync.Map      // 権限チェック結果キャッシュ map[string]*PermissionCache
	permissionCacheTTL    time.Duration // 権限チェック結果キャッシュ有効期限

	// メトリクス機能
	metrics *AuthorizationMetrics
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(policyStore PolicyStore, policyEngine *PolicyEngine) (*AuthorizationService, error) {
	// Casbinエンフォーサーの初期化
	rbacEnforcer, err := casbin.NewEnforcer("config/rbac_model.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RBAC enforcer: %w", err)
	}

	abacEnforcer, err := casbin.NewEnforcer("config/abac_model.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ABAC enforcer: %w", err)
	}

	// カスタム関数を追加
	abacEnforcer.AddFunction("contains", containsFunc)
	abacEnforcer.AddFunction("stringContains", stringContainsFunc)

	service := &AuthorizationService{
		policyStore:           policyStore,
		rbacEnforcer:          rbacEnforcer,
		abacEnforcer:          abacEnforcer,
		policyEngine:          policyEngine,
		policyRefreshInterval: 10 * time.Minute, // ポリシー再読み込み間隔
		permissionCacheTTL:    5 * time.Minute,  // 権限チェック結果キャッシュ有効期限
	}

	// メトリクス追跡を自動有効化
	service.AddMetricsTracking()

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
			s.abacEnforcer.AddPolicy(policy.Condition, policy.Resource, policy.Action)
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

	// ポリシー最終更新時刻を記録
	s.lastPolicyRefreshTime = time.Now()

	return nil
}

// CheckPermission は権限をチェック（キャッシュ機能付き）
func (s *AuthorizationService) CheckPermission(user *model.User, resource, action string, resourceID *string) (bool, error) {
	startTime := time.Now()

	// Generate cache key
	cacheKey := s.generateCacheKey(user, resource, action, resourceID)

	// Check cache first
	if cached, found := s.permissionCache.Load(cacheKey); found {
		if entry, ok := cached.(PermissionCache); ok && time.Now().Before(entry.expiresAt) {
			// Record cache hit metrics
			if s.metrics != nil {
				s.metrics.mu.Lock()
				s.metrics.CacheHits++
				s.metrics.mu.Unlock()
			}
			s.trackMetrics(true, nil, time.Since(startTime), false)
			return entry.allowed, nil
		}
	}

	// Record cache miss
	if s.metrics != nil {
		s.metrics.mu.Lock()
		s.metrics.CacheMisses++
		s.metrics.mu.Unlock()
	}

	// Perform actual permission check
	allowed, err := s.checkPermissionInternal(user, resource, action, resourceID)
	if err != nil {
		// Record failed request metrics
		s.trackMetrics(false, err, time.Since(startTime), false)
		return false, err
	}

	// Cache the result
	s.permissionCache.Store(cacheKey, PermissionCache{
		allowed:   allowed,
		expiresAt: time.Now().Add(s.permissionCacheTTL),
	})

	// Record successful request metrics
	s.trackMetrics(true, nil, time.Since(startTime), false)
	return allowed, nil
}

// checkPermissionInternal performs the actual permission check
func (s *AuthorizationService) checkPermissionInternal(user *model.User, resource, action string, resourceID *string) (bool, error) {
	// ポリシーキャッシュの有効性チェック
	if time.Since(s.lastPolicyRefreshTime) > s.policyRefreshInterval {
		if err := s.RefreshPolicies(context.Background()); err != nil {
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
	if resourceID != nil {
		abacAllowed, err := s.checkABACPermission(user, *resourceID, action)
		if err != nil {
			return false, err
		}
		return abacAllowed, nil
	}

	return rbacAllowed, nil
}

// checkRBACPermission はRBACによる権限チェック
func (s *AuthorizationService) checkRBACPermission(user *model.User, resource, action string) (bool, error) {
	allowed, err := s.rbacEnforcer.Enforce(user.Role, resource, action)
	if err != nil {
		return false, fmt.Errorf("RBAC permission check failed: %w", err)
	}

	return allowed, nil
}

// checkABACPermission はABACによる権限チェック
func (s *AuthorizationService) checkABACPermission(user *model.User, resource, action string) (bool, error) {
	// First, try to use the structured policy engine if available
	if s.policyEngine != nil && strings.HasPrefix(resource, "product_") {
		// Extract product ID from resource (e.g., "product_123" -> "123")
		productID := strings.TrimPrefix(resource, "product_")
		allowed, err := s.policyEngine.EvaluateProductAccess(context.Background(), user, productID, action)
		if err == nil {
			return allowed, nil
		}
		// If policy engine fails, fall back to casbin
		fmt.Printf("Policy engine evaluation failed, falling back to casbin: %v\n", err)
	}

	// Fallback to casbin ABAC
	userRequest := &model.UserRequest{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
		Age:      user.Age,
		Location: user.Location,
		Premium:  user.Premium,
		VIPLevel: user.VIPLevel,
	}

	allowed, err := s.abacEnforcer.Enforce(userRequest, resource, action)
	if err != nil {
		return false, fmt.Errorf("ABAC permission check failed: %w", err)
	}

	return allowed, nil
}

// AddProductPolicy は商品固有のポリシーを追加
func (s *AuthorizationService) AddProductPolicy(ctx context.Context, productID string, policy ProductPolicy, createdBy string) error {
	rule := PolicyRule{
		Type:      "abac",
		Subject:   policy.SubjectRule,
		Resource:  "product_" + productID,
		Action:    policy.Action,
		Effect:    "allow",
		CreatedBy: createdBy,
	}

	if err := s.policyStore.SavePolicy(ctx, rule); err != nil {
		return fmt.Errorf("failed to save product policy: %w", err)
	}

	// 監査ログの記録
	change := PolicyChange{
		Type:      "product_policy_add",
		After:     rule,
		ChangedBy: createdBy,
		Reason:    fmt.Sprintf("Product policy added for product %s", productID),
	}

	if err := s.policyStore.LogPolicyChange(ctx, change); err != nil {
		fmt.Printf("Warning: failed to log policy change: %v\n", err)
	}

	return s.RefreshPolicies(ctx)
}

// ProductPolicy は商品固有のポリシー定義
type ProductPolicy struct {
	SubjectRule string `json:"subject_rule"`
	Action      string `json:"action"`
	AgeLimit    int    `json:"age_limit"`
	Category    string `json:"category"`
	IsAdult     bool   `json:"is_adult"`
	Region      string `json:"region"`
	VIPLevel    int    `json:"vip_level"`
}

// AddPolicy は新しいポリシーを追加
func (s *AuthorizationService) AddPolicy(ctx context.Context, policyType, subject, resource, action, createdBy string) error {
	rule := PolicyRule{
		Type:      policyType,
		Subject:   subject,
		Resource:  resource,
		Action:    action,
		Effect:    "allow",
		CreatedBy: createdBy,
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
		"total_policies":          len(policies),
		"rbac_policies":           0,
		"abac_policies":           0,
		"total_roles":             len(roles),
		"last_policy_refresh":     s.lastPolicyRefreshTime,
		"policy_refresh_interval": s.policyRefreshInterval,
	}

	for _, policy := range policies {
		switch policy.Type {
		case "rbac":
			stats["rbac_policies"] = stats["rbac_policies"].(int) + 1
		case "abac":
			stats["abac_policies"] = stats["abac_policies"].(int) + 1
		}
	}

	return stats, nil
}

// generateCacheKey generates a cache key for permission checks
func (s *AuthorizationService) generateCacheKey(user *model.User, resource, action string, resourceID *string) string {
	parts := []string{user.ID, resource, action}
	if resourceID != nil {
		parts = append(parts, *resourceID)
	}
	return strings.Join(parts, ":")
}

// ClearCache clears the permission cache
func (s *AuthorizationService) ClearCache() {
	s.permissionCache = sync.Map{}
}

// ClearUserCache clears cache entries for a specific user
func (s *AuthorizationService) ClearUserCache(userID string) {
	s.permissionCache.Range(func(key, value interface{}) bool {
		if cacheKey, ok := key.(string); ok && strings.HasPrefix(cacheKey, userID+":") {
			s.permissionCache.Delete(key)
		}
		return true
	})
}

// BulkPermissionRequest represents a request for bulk permission checking
type BulkPermissionRequest struct {
	User        *model.User
	Resource    string
	Action      string
	ResourceIDs []string
}

// BulkPermissionResult represents the result of bulk permission checking
type BulkPermissionResult struct {
	AllowedIDs []string
	DeniedIDs  []string
}

// CheckBulkPermissions performs bulk permission checking for multiple resources
// This implements PDP-Level Filtering with Information Graph pattern
func (s *AuthorizationService) CheckBulkPermissions(ctx context.Context, request BulkPermissionRequest) (*BulkPermissionResult, error) {
	startTime := time.Now()

	result := &BulkPermissionResult{
		AllowedIDs: make([]string, 0),
		DeniedIDs:  make([]string, 0),
	}

	// ポリシーキャッシュの有効性チェック
	if time.Since(s.lastPolicyRefreshTime) > s.policyRefreshInterval {
		if err := s.RefreshPolicies(ctx); err != nil {
			return nil, fmt.Errorf("failed to refresh policies: %w", err)
		}
	}

	// バルクでRBAC権限をチェック
	rbacAllowed, err := s.checkRBACPermission(request.User, request.Resource, request.Action)
	if err != nil {
		return nil, fmt.Errorf("RBAC bulk check failed: %w", err)
	}

	// RBACで許可されていない場合は全て拒否
	if !rbacAllowed {
		result.DeniedIDs = request.ResourceIDs
		return result, nil
	}

	// 各リソースIDに対してABACチェック（並列処理で最適化）
	type checkResult struct {
		id      string
		allowed bool
		err     error
	}

	resultChan := make(chan checkResult, len(request.ResourceIDs))
	semaphore := make(chan struct{}, 10) // 同時実行数を制限

	for _, resourceID := range request.ResourceIDs {
		go func(id string) {
			semaphore <- struct{}{}        // セマフォ獲得
			defer func() { <-semaphore }() // セマフォ解放

			// キャッシュからチェック
			cacheKey := s.generateCacheKey(request.User, request.Resource, request.Action, &id)
			if cached, found := s.permissionCache.Load(cacheKey); found {
				if entry, ok := cached.(PermissionCache); ok && time.Now().Before(entry.expiresAt) {
					resultChan <- checkResult{id: id, allowed: entry.allowed}
					return
				}
			}

			// ABACチェック
			allowed, err := s.checkABACPermission(request.User, id, request.Action)
			if err != nil {
				resultChan <- checkResult{id: id, allowed: false, err: err}
				return
			}

			// 結果をキャッシュ
			s.permissionCache.Store(cacheKey, PermissionCache{
				allowed:   allowed,
				expiresAt: time.Now().Add(s.permissionCacheTTL),
			})

			resultChan <- checkResult{id: id, allowed: allowed}
		}(resourceID)
	}

	// 結果を収集
	for i := 0; i < len(request.ResourceIDs); i++ {
		res := <-resultChan
		if res.err != nil {
			// Record failed bulk request metrics
			s.trackMetrics(false, res.err, time.Since(startTime), true)
			return nil, fmt.Errorf("permission check failed for resource %s: %w", res.id, res.err)
		}
		if res.allowed {
			result.AllowedIDs = append(result.AllowedIDs, res.id)
		} else {
			result.DeniedIDs = append(result.DeniedIDs, res.id)
		}
	}

	// Record successful bulk request metrics
	s.trackMetrics(true, nil, time.Since(startTime), true)
	return result, nil
}

// GetAccessibleResourceIDs returns only the resource IDs that the user can access
// This is the core of PDP-Level Filtering with Information Graph
func (s *AuthorizationService) GetAccessibleResourceIDs(ctx context.Context, user *model.User, resource, action string, candidateIDs []string) ([]string, error) {
	if len(candidateIDs) == 0 {
		return []string{}, nil
	}

	request := BulkPermissionRequest{
		User:        user,
		Resource:    resource,
		Action:      action,
		ResourceIDs: candidateIDs,
	}

	result, err := s.CheckBulkPermissions(ctx, request)
	if err != nil {
		return nil, err
	}

	return result.AllowedIDs, nil
}

// PartialEvaluationRequest represents a request for partial policy evaluation
type PartialEvaluationRequest struct {
	User     *model.User
	Resource string
	Action   string
}

// PartialEvaluationResult represents the result of partial policy evaluation
type PartialEvaluationResult struct {
	SQLCondition     string                 `json:"sql_condition"`
	BindParameters   map[string]interface{} `json:"bind_parameters"`
	CanOptimize      bool                   `json:"can_optimize"`
	UnsupportedRules []string               `json:"unsupported_rules"`
}

// PartiallyEvaluateToSQL converts policies to SQL WHERE conditions for database-level filtering
func (s *AuthorizationService) PartiallyEvaluateToSQL(ctx context.Context, request PartialEvaluationRequest) (*PartialEvaluationResult, error) {
	startTime := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.mu.Lock()
			s.metrics.PartialEvaluationCount++
			s.metrics.mu.Unlock()
		}
		s.trackMetrics(true, nil, time.Since(startTime), false)
	}()

	// First check RBAC - if user doesn't have basic access, return restrictive condition
	rbacAllowed, err := s.checkRBACPermission(request.User, request.Resource, request.Action)
	if err != nil {
		return nil, fmt.Errorf("RBAC check failed: %w", err)
	}

	if !rbacAllowed {
		return &PartialEvaluationResult{
			SQLCondition:   "1 = 0", // Always false - no access
			BindParameters: make(map[string]interface{}),
			CanOptimize:    true,
		}, nil
	}

	// Generate user-attribute-based SQL conditions
	conditions := s.generateUserAttributeConditions(request.User)
	bindParams := make(map[string]interface{})

	// Basic user attribute bindings
	bindParams["user_id"] = request.User.ID
	bindParams["user_role"] = request.User.Role
	bindParams["user_age"] = request.User.Age
	bindParams["user_location"] = request.User.Location
	bindParams["user_premium"] = request.User.Premium
	bindParams["user_vip_level"] = request.User.VIPLevel

	var sqlCondition string
	if len(conditions) > 0 {
		sqlCondition = strings.Join(conditions, " OR ")
	} else {
		// Fallback to permissive condition if no specific rules can be converted
		sqlCondition = "1 = 1" // Always true - will be filtered by application-level checks
	}

	return &PartialEvaluationResult{
		SQLCondition:   sqlCondition,
		BindParameters: bindParams,
		CanOptimize:    len(conditions) > 0,
	}, nil
}

// generateUserAttributeConditions generates SQL conditions based on common user attribute patterns
func (s *AuthorizationService) generateUserAttributeConditions(user *model.User) []string {
	var conditions []string

	// Age-based conditions
	if user.Age >= 18 {
		conditions = append(conditions, "age_restriction <= :user_age OR age_restriction IS NULL")
	}

	// Premium user conditions
	if user.Premium {
		conditions = append(conditions, "premium_only = false OR premium_only IS NULL")
	} else {
		conditions = append(conditions, "premium_only = false OR premium_only IS NULL")
	}

	// VIP level conditions
	if user.VIPLevel > 0 {
		conditions = append(conditions, "vip_level_required <= :user_vip_level OR vip_level_required IS NULL")
	}

	// Location-based conditions (simplified)
	if user.Location != "" {
		conditions = append(conditions, "location_restriction = :user_location OR location_restriction IS NULL")
	}

	// Role-based conditions
	switch user.Role {
	case "admin":
		conditions = append(conditions, "1 = 1") // Admin can see everything
	case "manager":
		conditions = append(conditions, "visibility IN ('public', 'internal') OR created_by = :user_id")
	case "user":
		conditions = append(conditions, "visibility = 'public' OR created_by = :user_id")
	}

	return conditions
}

// EvaluateUserAccessSQL is a helper method for other packages to get SQL conditions
func (s *AuthorizationService) EvaluateUserAccessSQL(ctx context.Context, user *model.User, resource, action string) (string, map[string]interface{}, error) {
	request := PartialEvaluationRequest{
		User:     user,
		Resource: resource,
		Action:   action,
	}

	result, err := s.PartiallyEvaluateToSQL(ctx, request)
	if err != nil {
		return "", nil, err
	}

	return result.SQLCondition, result.BindParameters, nil
}

// AddMetricsTracking enables metrics tracking for the authorization service
func (s *AuthorizationService) AddMetricsTracking() {
	s.metrics = &AuthorizationMetrics{
		LastResetTime: time.Now(),
	}
}

// GetMetrics returns current authorization metrics
func (s *AuthorizationService) GetMetrics() *AuthorizationMetrics {
	if s.metrics == nil {
		return &AuthorizationMetrics{}
	}

	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions (excluding mutex)
	metrics := AuthorizationMetrics{
		TotalRequests:          s.metrics.TotalRequests,
		SuccessfulRequests:     s.metrics.SuccessfulRequests,
		FailedRequests:         s.metrics.FailedRequests,
		CacheHits:              s.metrics.CacheHits,
		CacheMisses:            s.metrics.CacheMisses,
		AverageResponseTime:    s.metrics.AverageResponseTime,
		BulkRequestCount:       s.metrics.BulkRequestCount,
		PartialEvaluationCount: s.metrics.PartialEvaluationCount,
		LastResetTime:          s.metrics.LastResetTime,
	}

	// Calculate cache hit rate
	totalCacheChecks := metrics.CacheHits + metrics.CacheMisses
	if totalCacheChecks > 0 {
		metrics.CacheHitRate = float64(metrics.CacheHits) / float64(totalCacheChecks)
	}

	return &metrics
}

// ResetMetrics resets all metrics counters
func (s *AuthorizationService) ResetMetrics() {
	if s.metrics != nil {
		s.metrics.mu.Lock()
		defer s.metrics.mu.Unlock()

		*s.metrics = AuthorizationMetrics{
			LastResetTime: time.Now(),
		}
	}
}

// trackMetrics records metrics for authorization requests
func (s *AuthorizationService) trackMetrics(success bool, err error, responseTime time.Duration, isBulk bool) {
	if s.metrics == nil {
		return
	}

	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	s.metrics.TotalRequests++
	s.metrics.totalResponseTime += responseTime

	if success {
		s.metrics.SuccessfulRequests++
	} else {
		s.metrics.FailedRequests++
	}

	if isBulk {
		s.metrics.BulkRequestCount++
	}

	// Update average response time
	if s.metrics.TotalRequests > 0 {
		s.metrics.AverageResponseTime = s.metrics.totalResponseTime / time.Duration(s.metrics.TotalRequests)
	}

	// Update cache hit rate
	totalCacheChecks := s.metrics.CacheHits + s.metrics.CacheMisses
	if totalCacheChecks > 0 {
		s.metrics.CacheHitRate = float64(s.metrics.CacheHits) / float64(totalCacheChecks)
	}
}
