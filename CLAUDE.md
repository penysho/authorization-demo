# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based authorization demo application showcasing RBAC (Role-Based Access Control) and ABAC (Attribute-Based Access Control) using Casbin. It simulates an e-commerce backend API with sophisticated product access control based on user attributes like age, location, VIP level, and time-based restrictions.

## Tech Stack

- **Go 1.23+** - Main language
- **Gin Web Framework** - HTTP server and routing
- **Casbin v2** - Authorization library for RBAC/ABAC
- **GORM** - ORM for database operations
- **PostgreSQL** - Database (via docker-compose)
- **JWT** - Authentication tokens
- **Docker Compose** - Local development environment

## Development Commands

### Running the Application
```bash
# Start dependencies (PostgreSQL)
docker-compose up -d

# Install dependencies
go mod tidy

# Run the application
go run main.go
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for specific package
go test ./internal/service/
```

### Code Quality
```bash
# Format code
go fmt ./...

# Run linter (if golangci-lint is installed)
golangci-lint run

# Vet code
go vet ./...
```

## Architecture Overview

### Core Components

1. **Authentication Service** (`internal/service/authentication.go`)
   - JWT token generation/validation
   - User authentication logic

2. **Authorization Service** (`internal/service/authorization.go`)
   - Casbin policy enforcement
   - RBAC and ABAC decision making

3. **Policy Engines**:
   - **Casbin Policy Store** (`internal/service/casbin_policy_store.go`) - Database-backed policy storage
   - **Structured Policy Engine** (`internal/service/structured_policy_engine.go`) - Custom policy engine with templates

4. **Product Service** (`internal/service/product.go`)
   - Product CRUD operations
   - Integration with authorization checks

5. **Middleware** (`internal/middleware/`)
   - Authentication middleware for JWT validation
   - Authorization middleware for permission checking

### Authorization Models

- **RBAC Model** (`config/rbac_model.conf`) - Role-based access control
- **ABAC Model** (`config/abac_model.conf`) - Attribute-based access control with expression evaluation

### Key Features

- **Multi-layered authorization**: RBAC for basic permissions, ABAC for complex attribute-based rules
- **Age-based restrictions**: Products with age limits (alcohol, adult content)
- **Geographic restrictions**: Region-specific product availability
- **VIP level controls**: Premium content access based on user tier
- **Time-based restrictions**: Time-sensitive access controls
- **Policy templates**: Pre-built policy templates for common scenarios
- **Audit logging**: Comprehensive access control audit trail

## Test Users

The application includes sample users for testing:

- **alice** (admin): Full access, age 30, JP location, VIP level 5
- **bob** (operator): Read/write access, age 25, US location, VIP level 3  
- **charlie** (customer): Read-only, age 17, JP location, VIP level 0
- **dave** (customer): Read-only, age 22, EU location, VIP level 1

All users use password: `password123`

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login

### Product Management
- `GET /api/products` - List products (with authorization filtering)
- `GET /api/products/:id` - Get product details
- `POST /api/products` - Create product (admin only)
- `PUT /api/products/:id` - Update product
- `DELETE /api/products/:id` - Delete product

### Policy Management
- `POST /api/casbin/policies` - Create Casbin policy
- `POST /api/casbin/roles/assign` - Assign roles
- `POST /api/structured-policy/products/:id` - Create structured policy
- `GET /api/structured-policy/templates` - Get policy templates

### Development Utilities
- `GET /health` - Health check
- `GET /` - API documentation and feature overview

## Database Schema

The application uses GORM auto-migration for:
- **Users**: Basic user information with attributes for ABAC
- **Products**: Product catalog with access control metadata
- **Policies**: Casbin policy storage
- **Audit logs**: Authorization decision tracking

## Configuration

- Database connection configured via environment variables or defaults to local PostgreSQL
- JWT secret key should be set via environment variable `JWT_SECRET`
- Server port configurable via `PORT` environment variable (default: 8080)

## Development Notes

- The application automatically creates sample data on first run
- Policy evaluation uses Casbin's expression evaluator for ABAC rules
- Authorization decisions are cached for performance
- All authorization checks are logged for audit purposes
- The structured policy engine provides a more user-friendly alternative to raw Casbin policies