# Authorization Demo

This project demonstrates the implementation of authorization mechanisms using **RBAC (Role-Based Access Control)** and **ABAC (Attribute-Based Access Control)** with Go and the Casbin library.

## Features

- **RBAC (Role-Based Access Control)**: Manages permissions based on user roles.
- **ABAC (Attribute-Based Access Control)**: Grants permissions based on user and resource attributes.
- **Generic Resource-Based Policies**: Support for any resource type (products, orders, customers, etc.)
- **Structured Policy Engine**: Flexible policy conditions with AND/OR logic
- **Time-based Restrictions**: Support for business hours and time zones
- **Advanced Filtering**: PDP-level filtering with partial evaluation
- **Dual authorization engines**: Casbin-based and custom structured policy engine
- **Audit Logging**: Tracks all policy changes and access decisions
- **Performance Metrics**: Built-in metrics tracking for authorization decisions

## Generic ABAC System

The system supports attribute-based access control for any resource type:

### Supported Resource Types

- **Product**: Product catalog with price, category, age restrictions
- **Order**: Customer orders with amount, status, priority
- **Customer**: Customer profiles with type, credit limit, risk score
- **Invoice**: Financial documents (extensible)
- **Report**: Business reports (extensible)

### Policy Structure

```json
{
  "resource_type": "order",
  "resource_id": "order_123",
  "policy_type": "allow",
  "conditions": [{
    "name": "High Value Order Restriction",
    "type": "simple",
    "conditions": [{
      "attribute": "amount",
      "operator": "<=",
      "value": 10000
    }]
  }]
}
```

### Resource-Specific Attributes

#### User Attributes

- `age`, `location`, `vip_level`, `premium`, `role`

#### Product Attributes

- `price`, `category`, `age_limit`, `region`, `is_adult`, `rating`

#### Order Attributes

- `amount`, `status`, `priority`, `region`, `days_old`

#### Customer Attributes

- `customer_type`, `credit_limit`, `total_purchases`, `account_status`
- `payment_terms`, `industry`, `employee_count`, `risk_score`, `account_age`

## Architecture

The project follows a layered architecture:

- **Handler Layer**: HTTP handlers for API endpoints
- **Service Layer**: Business logic and authorization services
- **Model Layer**: Data models and structures
- **Infrastructure Layer**: Database connections and migrations
- **Middleware Layer**: Authentication and authorization middleware

## API Endpoints

### Resource Policy Management

- `POST /api/structured-policies/resources` - Create/update resource policy
- `GET /api/structured-policies/resources` - Get resource policy
- `POST /api/structured-policies/test` - Test policy evaluation
- `GET /api/structured-policies/templates` - Get policy templates

### Other Endpoints

- Authentication, Products, Users, and Casbin policy management endpoints

## Installation

1. Clone the repository
2. Set up PostgreSQL database
3. Configure environment variables:

   ```bash
   DB_HOST=localhost
   DB_PORT=5432
   DB_USER=your_user
   DB_PASSWORD=your_password
   DB_NAME=authorization_demo
   DB_SSLMODE=disable
   ```

4. Run migrations: The application automatically runs migrations on startup
5. Start the server: `go run main.go`

## Usage Examples

### Creating a Policy for Orders

```bash
curl -X POST http://localhost:8080/api/structured-policies/resources \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_type": "order",
    "resource_id": "order_123",
    "policy_type": "allow",
    "conditions": [{
      "name": "VIP Orders Only",
      "type": "simple",
      "conditions": [{
        "attribute": "vip_level",
        "operator": ">=",
        "value": 3
      }]
    }]
  }'
```

### Creating a Policy for Customers

```bash
curl -X POST http://localhost:8080/api/structured-policies/resources \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_type": "customer",
    "resource_id": "cust_456",
    "policy_type": "allow",
    "conditions": [{
      "name": "Enterprise Customers",
      "type": "simple",
      "conditions": [{
        "attribute": "customer_type",
        "operator": "==",
        "value": "enterprise"
      }]
    }]
  }'
```

## Testing

The system includes comprehensive test scenarios for:

- User authentication and role assignment
- Product access based on user attributes
- Order processing with amount restrictions
- Customer profile access control
- Policy inheritance and priority handling

## License

MIT License
