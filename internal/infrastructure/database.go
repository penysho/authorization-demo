package infrastructure

import (
	"authorization-demo/internal/model"
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DatabaseConfig contains database connection configuration
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
	SSLMode  string
}

// DefaultDatabaseConfig returns default database configuration for development
func DefaultDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     getEnv("DB_PORT", "5437"),
		User:     getEnv("DB_USER", "postgres"),
		Password: getEnv("DB_PASSWORD", "postgres"),
		Database: getEnv("DB_NAME", "postgres"),
		SSLMode:  getEnv("DB_SSLMODE", "disable"),
	}
}

// ConnectDatabase establishes a connection to PostgreSQL database using GORM
func ConnectDatabase(config *DatabaseConfig) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		config.Host,
		config.Port,
		config.User,
		config.Password,
		config.Database,
		config.SSLMode,
	)

	gormConfig := &gorm.Config{
		Logger: logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold:             time.Second,
				LogLevel:                  logger.Silent, // Set to logger.Info for more verbose logging
				IgnoreRecordNotFoundError: true,
				Colorful:                  true,
			},
		),
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
	sqlDB.SetMaxIdleConns(10)

	// SetMaxOpenConns sets the maximum number of open connections to the database.
	sqlDB.SetMaxOpenConns(100)

	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// MigratePolicyStoreSchema performs database migration for policy store
func MigratePolicyStoreSchema(db *gorm.DB) error {
	return db.AutoMigrate(
		&model.CasbinPolicyRuleDB{},
		&model.CasbinRoleAssignmentDB{},
		&model.PolicyChangeDB{},
	)
}

// MigratePolicyEngineSchema migrates policy engine tables
func MigratePolicyEngineSchema(db *gorm.DB) error {
	// Create resource_access_policies table (new generic table)
	if err := db.AutoMigrate(&model.ResourceAccessPolicy{}); err != nil {
		return fmt.Errorf("failed to migrate ResourceAccessPolicy table: %w", err)
	}

	// Create policy_conditions table
	if err := db.AutoMigrate(&model.PolicyCondition{}); err != nil {
		return fmt.Errorf("failed to migrate PolicyCondition table: %w", err)
	}

	// Create indexes for better performance
	if err := createPolicyEngineIndexes(db); err != nil {
		return fmt.Errorf("failed to create policy engine indexes: %w", err)
	}

	return nil
}

// createPolicyEngineIndexes creates necessary indexes for policy engine tables
func createPolicyEngineIndexes(db *gorm.DB) error {
	// Index for resource_access_policies
	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_resource_access_policies_resource
		ON resource_access_policies(resource_type, resource_id)
	`).Error; err != nil {
		return err
	}

	// Composite index for policy_conditions on resource
	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_policy_conditions_resource_enabled
		ON policy_conditions(resource_type, resource_id, enabled)
	`).Error; err != nil {
		return err
	}

	// Index for policy_conditions priority
	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_policy_conditions_priority
		ON policy_conditions(priority DESC)
	`).Error; err != nil {
		return err
	}

	return nil
}

// MigrateAllSchemas performs all database migrations in the correct order
func MigrateAllSchemas(db *gorm.DB) error {
	// 1. First migrate core models
	if err := db.AutoMigrate(&model.User{}); err != nil {
		return fmt.Errorf("failed to migrate User table: %w", err)
	}

	if err := db.AutoMigrate(&model.Product{}); err != nil {
		return fmt.Errorf("failed to migrate Product table: %w", err)
	}

	if err := db.AutoMigrate(&model.Customer{}); err != nil {
		return fmt.Errorf("failed to migrate Customer table: %w", err)
	}

	if err := db.AutoMigrate(&model.Order{}); err != nil {
		return fmt.Errorf("failed to migrate Order table: %w", err)
	}

	// 2. Migrate Casbin policy tables
	if err := MigratePolicyStoreSchema(db); err != nil {
		return err
	}

	// 3. Migrate structured policy engine tables
	if err := MigratePolicyEngineSchema(db); err != nil {
		return err
	}

	// 4. Create additional indexes for better performance
	if err := createAdditionalIndexes(db); err != nil {
		return fmt.Errorf("failed to create additional indexes: %w", err)
	}

	return nil
}

// createAdditionalIndexes creates additional indexes for performance
func createAdditionalIndexes(db *gorm.DB) error {
	// Index for orders
	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_orders_customer_id
		ON orders(customer_id)
	`).Error; err != nil {
		return err
	}

	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_orders_product_id
		ON orders(product_id)
	`).Error; err != nil {
		return err
	}

	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_orders_status
		ON orders(status)
	`).Error; err != nil {
		return err
	}

	// Index for customers
	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_customers_user_id
		ON customers(user_id)
	`).Error; err != nil {
		return err
	}

	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_customers_customer_type
		ON customers(customer_type)
	`).Error; err != nil {
		return err
	}

	return nil
}

// getEnv gets environment variable with fallback
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
