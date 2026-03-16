# Authentication Module

## Overview

This module provides authentication and authorization for the Rho-AIAS firewall management API.

## Features

- **JWT-based Authentication**: Secure token-based authentication for human users
- **Password Security**: Bcrypt hashing with configurable cost
- **Captcha Support**: Image-based captcha to prevent brute force attacks
- **Role-based Access Control**: Admin and user roles

## Configuration

Add the following to your `config.yml`:

```yaml
auth:
  enabled: true                    # Enable authentication
  jwt_secret: ""                   # JWT secret (use env var JWT_SECRET)
  jwt_issuer: "rho-aias"           # JWT issuer
  token_duration: 1440             # Token duration in minutes (24 hours)
  database_path: "./data/auth.db"  # SQLite database path
  captcha_enabled: true            # Enable captcha
  captcha_duration: 5              # Captcha validity in minutes
```

## API Endpoints

### Public Endpoints (No Authentication Required)

- `GET /api/auth/captcha` - Get captcha image
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh token
- `POST /api/auth/logout` - User logout

### Protected Endpoints (Authentication Required)

- `GET /api/auth/me` - Get current user info
- `PUT /api/auth/password` - Change password

All firewall management APIs are protected when authentication is enabled.

## Default Credentials

On first startup with authentication enabled, a default admin user is created:

- **Username**: `admin`
- **Password**: `admin123`

**⚠️ Important**: Change the default password immediately after first login!

## Usage

### Login

```bash
# 1. Get captcha
curl http://localhost:8080/api/auth/captcha

# Response:
# {
#   "captcha_id": "xxx",
#   "image": "data:image/png;base64,..."
# }

# 2. Login with captcha
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123",
    "captcha_id": "xxx",
    "captcha_answer": "abcd"
  }'

# Response:
# {
#   "token": "eyJhbGciOiJIUzI1NiIs...",
#   "user": {...},
#   "expires_at": "2026-03-17T07:00:00Z"
# }
```

### Access Protected API

```bash
# Use the token in Authorization header
curl http://localhost:8080/api/manual/rules \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

## Security Recommendations

1. **JWT Secret**: Always set a strong JWT secret via environment variable:
   ```bash
   export JWT_SECRET="your-strong-secret-key-here"
   ```

2. **Password Policy**: Enforce strong passwords (minimum 6 characters)

3. **HTTPS**: Always use HTTPS in production

4. **Token Storage**: Store tokens securely on the client side

5. **Change Default Password**: Change the default admin password immediately

## Database

The authentication module uses SQLite with WAL mode for better concurrent performance.

Database tables:
- `users` - User accounts
- `api_keys` - API keys for automation (future feature)

## Future Enhancements

- [ ] API Key authentication for automation
- [ ] Casbin-based RBAC
- [ ] Audit logging
- [ ] Rate limiting
- [ ] Password strength validation
- [ ] Two-factor authentication
