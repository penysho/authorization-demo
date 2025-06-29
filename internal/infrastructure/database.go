package infrastructure

import (
	"authorization-demo/internal/service"
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
	store := service.NewDatabasePolicyStore(db)
	return store.AutoMigrate()
}

// MigratePolicyEngineSchema migrates policy engine tables
func MigratePolicyEngineSchema(db *gorm.DB) error {
	// Create product_access_policies table
	if err := db.AutoMigrate(&service.ProductAccessPolicy{}); err != nil {
		return fmt.Errorf("failed to migrate ProductAccessPolicy table: %w", err)
	}

	// Create policy_conditions table
	if err := db.AutoMigrate(&service.PolicyCondition{}); err != nil {
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
	// Index for product_access_policies
	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_product_access_policies_product_id
		ON product_access_policies(product_id)
	`).Error; err != nil {
		return err
	}

	// Composite index for policy_conditions
	if err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_policy_conditions_product_enabled
		ON policy_conditions(product_id, enabled)
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

// getEnv gets environment variable with fallback
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
