package model

import (
	"time"
)

// Customer represents a customer entity separate from user
type Customer struct {
	ID               string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID           string    `json:"user_id" gorm:"type:varchar(36);unique;index"`
	CompanyName      string    `json:"company_name"`
	CustomerType     string    `json:"customer_type"` // "individual", "business", "enterprise"
	CreditLimit      float64   `json:"credit_limit"`
	TotalPurchases   float64   `json:"total_purchases"`
	AccountStatus    string    `json:"account_status"` // "active", "suspended", "blacklisted"
	PaymentTerms     string    `json:"payment_terms"`  // "prepaid", "net30", "net60"
	Industry         string    `json:"industry"`
	EmployeeCount    int       `json:"employee_count"`
	AnnualRevenue    float64   `json:"annual_revenue"`
	RiskScore        int       `json:"risk_score"`        // 0-100
	PreferredContact string    `json:"preferred_contact"` // "email", "phone", "sms"
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// CustomerConditionAttributes defines attributes that can be used in customer-related ABAC policies
type CustomerConditionAttributes struct {
	CustomerType   string  `json:"customer_type"`
	CreditLimit    float64 `json:"credit_limit"`
	TotalPurchases float64 `json:"total_purchases"`
	AccountStatus  string  `json:"account_status"`
	PaymentTerms   string  `json:"payment_terms"`
	Industry       string  `json:"industry"`
	EmployeeCount  int     `json:"employee_count"`
	RiskScore      int     `json:"risk_score"`
	AccountAge     int     `json:"account_age"` // days since created
}
