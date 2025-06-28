package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"authorization-demo/internal/model"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// UserService はユーザー管理サービスのインターフェース
type UserService interface {
	CreateUser(ctx context.Context, req *CreateUserRequest) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	UpdateUser(ctx context.Context, id string, req *UpdateUserRequest) (*model.User, error)
	DeleteUser(ctx context.Context, id string) error
	ValidatePassword(ctx context.Context, username, password string) (*model.User, error)
	ListUsers(ctx context.Context, filters UserFilters) ([]model.User, error)
}

// CreateUserRequest はユーザー作成リクエスト
type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role" binding:"required"`
	Age      int    `json:"age"`
	Location string `json:"location"`
	Premium  bool   `json:"premium"`
	VIPLevel int    `json:"vip_level"`
}

// UpdateUserRequest はユーザー更新リクエスト
type UpdateUserRequest struct {
	Password *string `json:"password,omitempty"`
	Role     *string `json:"role,omitempty"`
	Age      *int    `json:"age,omitempty"`
	Location *string `json:"location,omitempty"`
	Premium  *bool   `json:"premium,omitempty"`
	VIPLevel *int    `json:"vip_level,omitempty"`
}

// UserFilters はユーザーフィルタリング条件
type UserFilters struct {
	Role     string
	MinAge   int
	MaxAge   int
	Location string
	Premium  *bool
	VIPLevel int
}

// userServiceImpl はユーザーサービスの実装
type userServiceImpl struct {
	db *gorm.DB
}

// NewUserService は新しいユーザーサービスを作成
func NewUserService(db *gorm.DB) UserService {
	return &userServiceImpl{db: db}
}

// CreateUser は新しいユーザーを作成
func (s *userServiceImpl) CreateUser(ctx context.Context, req *CreateUserRequest) (*model.User, error) {
	// パスワードをハッシュ化
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &model.User{
		ID:       generateUserID(),
		Username: req.Username,
		Password: hashedPassword,
		Role:     req.Role,
		Age:      req.Age,
		Location: req.Location,
		Premium:  req.Premium,
		VIPLevel: req.VIPLevel,
	}

	if err := s.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// パスワードを除去してレスポンス
	user.Password = ""
	return user, nil
}

// GetUserByID はIDでユーザーを取得
func (s *userServiceImpl) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// パスワードを除去
	user.Password = ""
	return &user, nil
}

// GetUserByUsername はユーザー名でユーザーを取得
func (s *userServiceImpl) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User
	if err := s.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found: %s", username)
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// ValidatePassword はユーザー名とパスワードを検証
func (s *userServiceImpl) ValidatePassword(ctx context.Context, username, password string) (*model.User, error) {
	user, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// パスワード検証
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	// パスワードを除去してレスポンス
	user.Password = ""
	return user, nil
}

// UpdateUser はユーザー情報を更新
func (s *userServiceImpl) UpdateUser(ctx context.Context, id string, req *UpdateUserRequest) (*model.User, error) {
	user, err := s.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// パスワードが指定されている場合はハッシュ化
	if req.Password != nil {
		hashedPassword, err := hashPassword(*req.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		user.Password = hashedPassword
	}

	// その他のフィールドを更新
	if req.Role != nil {
		user.Role = *req.Role
	}
	if req.Age != nil {
		user.Age = *req.Age
	}
	if req.Location != nil {
		user.Location = *req.Location
	}
	if req.Premium != nil {
		user.Premium = *req.Premium
	}
	if req.VIPLevel != nil {
		user.VIPLevel = *req.VIPLevel
	}

	if err := s.db.WithContext(ctx).Save(user).Error; err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// パスワードを除去してレスポンス
	user.Password = ""
	return user, nil
}

// DeleteUser はユーザーを削除
func (s *userServiceImpl) DeleteUser(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Where("id = ?", id).Delete(&model.User{}).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// ListUsers はユーザー一覧を取得
func (s *userServiceImpl) ListUsers(ctx context.Context, filters UserFilters) ([]model.User, error) {
	query := s.db.WithContext(ctx).Model(&model.User{})

	// フィルタを適用
	if filters.Role != "" {
		query = query.Where("role = ?", filters.Role)
	}
	if filters.MinAge > 0 {
		query = query.Where("age >= ?", filters.MinAge)
	}
	if filters.MaxAge > 0 {
		query = query.Where("age <= ?", filters.MaxAge)
	}
	if filters.Location != "" {
		query = query.Where("location = ?", filters.Location)
	}
	if filters.Premium != nil {
		query = query.Where("premium = ?", *filters.Premium)
	}
	if filters.VIPLevel > 0 {
		query = query.Where("vip_level >= ?", filters.VIPLevel)
	}

	var users []model.User
	if err := query.Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// パスワードを除去
	for i := range users {
		users[i].Password = ""
	}

	return users, nil
}

// hashPassword はパスワードをハッシュ化
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// generateUserID はユーザーIDを生成
func generateUserID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
