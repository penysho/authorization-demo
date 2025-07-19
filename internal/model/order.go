package model

import (
	"time"
)

// Order represents a customer order
type Order struct {
	ID         string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CustomerID string    `json:"customer_id" gorm:"type:varchar(36);not null;index"`
	ProductID  string    `json:"product_id" gorm:"type:varchar(36);not null;index"`
	Amount     float64   `json:"amount"`
	Status     string    `json:"status"`   // "pending", "confirmed", "shipped", "delivered", "cancelled"
	Priority   string    `json:"priority"` // "normal", "high", "urgent"
	Region     string    `json:"region"`   // shipping region
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// OrderConditionAttributes defines attributes that can be used in order-related ABAC policies
type OrderConditionAttributes struct {
	Amount       float64 `json:"amount"`
	Status       string  `json:"status"`
	Priority     string  `json:"priority"`
	Region       string  `json:"region"`
	CustomerType string  `json:"customer_type"` // derived from customer
	DaysOld      int     `json:"days_old"`      // calculated from created_at
}
