# CertVault CLI

A command-line interface for managing certificates with the CertVault API.

## Installation

```bash
go install github.com/gregPerlinLi/CertVaultCLI@latest
```

Or build from source:

```bash
git clone https://github.com/gregPerlinLi/CertVaultCLI.git
cd CertVaultCLI
make build
```

## Configuration

```bash
# Set the API endpoint (default: http://127.0.0.1:1888)
cv config set-url https://your-certvault-server.com

# Show current endpoint
cv config get-url
```

## Usage

### Authentication

```bash
cv login                        # Interactive login
cv login -u admin -p secret     # Non-interactive (not recommended)
cv logout
```

### User Profile

```bash
cv profile                      # Show current user profile
cv profile update --display-name "New Name" --email new@example.com
cv profile update --password    # Change password (interactive)
```

### Sessions

```bash
cv session list                 # List your login sessions
cv session logout <uuid>        # Logout a specific session
cv session logout-all           # Logout all sessions
```

### CA Certificates (User)

```bash
cv ca list                      # List your allocated CAs
cv ca get-cert <uuid>           # Print CA certificate PEM
cv ca get-cert <uuid> -o ca.pem # Save to file
cv ca get-cert <uuid> --chain   # Get full certificate chain
cv ca get-cert <uuid> -a        # Analyze certificate details
```

### SSL Certificates (User)

```bash
cv cert list                           # List your SSL certificates
cv cert get-cert <uuid>                # Print certificate PEM
cv cert get-cert <uuid> -o cert.pem    # Save to file
cv cert get-cert <uuid> -a             # Analyze certificate
cv cert get-privkey <uuid>             # Get private key (interactive password)
cv cert get-privkey <uuid> -o key.pem  # Save private key to file
cv cert update-comment <uuid> "My cert"
```

### Admin Commands

```bash
cv admin users                         # List all users
cv admin ca list                       # List all CAs
cv admin ca get-cert <uuid>            # Get CA certificate
cv admin ca get-privkey <uuid>         # Get CA private key
cv admin ca update-comment <uuid> "comment"
cv admin ca toggle-available <uuid>    # Toggle CA availability
cv admin ca import --cert-file ca.pem --key-file ca.key --comment "My CA"
cv admin ca bind <ca-uuid> user1 user2
cv admin ca unbind <ca-uuid> user1
cv admin ca bound-users <ca-uuid>
cv admin ca unbound-users <ca-uuid>
cv admin ca create-root --common-name "My Root CA" --not-after 2030-01-01
cv admin ca create-int --parent-ca <uuid> --common-name "My Int CA" --not-after 2028-01-01
cv admin cert issue --ca-uuid <uuid> --common-name example.com --not-after 2026-01-01
cv admin cert renew <uuid>
cv admin cert delete <uuid>
```

### Superadmin Commands

```bash
cv superadmin sessions                         # List all sessions
cv superadmin user-sessions <username>         # List a user's sessions
cv superadmin force-logout <username>          # Force logout a user
cv superadmin create-user --username bob --email bob@example.com --role user
cv superadmin update-user <username> --display-name "Bob Smith"
cv superadmin update-role <username> admin
cv superadmin delete-user <username>
cv superadmin count-ca
cv superadmin count-cert
```

## Project Structure

```
.
├── cmd/                    # Cobra CLI commands
│   ├── root.go
│   ├── login.go
│   ├── logout.go
│   ├── config.go
│   ├── profile.go
│   ├── session.go
│   ├── ca.go
│   ├── cert.go
│   ├── admin.go
│   └── superadmin.go
├── internal/
│   ├── api/                # HTTP client and API types
│   │   ├── client.go
│   │   ├── types.go
│   │   ├── auth.go
│   │   ├── user.go
│   │   ├── admin.go
│   │   └── superadmin.go
│   ├── config/             # Configuration management
│   │   └── config.go
│   └── ui/                 # Terminal UI helpers
│       ├── styles.go
│       ├── table.go
│       ├── spinner.go
│       └── prompts.go
├── main.go
├── go.mod
└── Makefile
```

## License

MIT
