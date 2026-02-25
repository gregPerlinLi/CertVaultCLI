package api

import "encoding/json"

// ResultVO is the generic API response wrapper
type ResultVO[T any] struct {
	Code      int    `json:"code"`
	Msg       string `json:"msg"`
	Data      T      `json:"data"`
	Timestamp string `json:"timestamp"`
}

// PageDTO is a paginated response
type PageDTO[T any] struct {
	Total int64 `json:"total"`
	List  []T   `json:"list"`
}

// UserProfileDTO represents a user profile
type UserProfileDTO struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Role        int32  `json:"role"`
}

// RoleName returns a human-readable role name
func (u *UserProfileDTO) RoleName() string {
	switch u.Role {
	case 1:
		return "User"
	case 2:
		return "Admin"
	case 3:
		return "Superadmin"
	default:
		return "Unknown"
	}
}

// CaInfoDTO represents a CA certificate info
type CaInfoDTO struct {
	UUID       string `json:"uuid"`
	Owner      string `json:"owner"`
	AllowSubCa bool   `json:"allowSubCa"`
	Comment    string `json:"comment"`
	Available  bool   `json:"available"`
	NotBefore  string `json:"notBefore"`
	NotAfter   string `json:"notAfter"`
	ParentCa   string `json:"parentCa"`
}

// CAType returns the type of CA as a string
func (c *CaInfoDTO) CAType() string {
	if c.ParentCa == "" {
		return "Root CA"
	} else if c.AllowSubCa {
		return "Int CA"
	}
	return "Leaf CA"
}

// CertInfoDTO represents an SSL certificate info
type CertInfoDTO struct {
	UUID       string `json:"uuid"`
	CaUUID     string `json:"caUuid"`
	Owner      string `json:"owner"`
	Comment    string `json:"comment"`
	NotBefore  string `json:"notBefore"`
	NotAfter   string `json:"notAfter"`
	CreatedAt  string `json:"createdAt"`
	ModifiedAt string `json:"modifiedAt"`
}

// LoginRecordDTO represents a login session record
type LoginRecordDTO struct {
	UUID      string `json:"uuid"`
	Username  string `json:"username"`
	IPAddress string `json:"ipAddress"`
	Region    string `json:"region"`
	Province  string `json:"province"`
	City      string `json:"city"`
	Browser   string `json:"browser"`
	OS        string `json:"os"`
	Platform  string `json:"platform"`
	LoginTime string `json:"loginTime"`
	IsOnline  bool   `json:"isOnline"`
}

// CreateUserDTO is used to create a new user
type CreateUserDTO struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        int32  `json:"role"`
}

// UpdateUserProfileDTO is used to update user profile
type UpdateUserProfileDTO struct {
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	OldPassword string `json:"oldPassword,omitempty"`
	NewPassword string `json:"newPassword,omitempty"`
}

// UpdateRoleDTO is used to update a user's role
type UpdateRoleDTO struct {
	Username string `json:"username"`
	Role     int32  `json:"role"`
}

// SubjectAltName represents a single Subject Alternative Name entry
type SubjectAltName struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// RequestCertDTO is the unified DTO for requesting both CA and SSL certificates.
// For CA requests (POST /api/v1/admin/cert/ca), populate CaUUID (omit for Root CA) and AllowSubCa.
// For SSL cert requests (POST /api/v1/user/cert/ssl), populate CaUUID (signing CA) and SubjectAltNames.
type RequestCertDTO struct {
	CaUUID             string           `json:"caUuid,omitempty"`
	AllowSubCa         bool             `json:"allowSubCa,omitempty"`
	Algorithm          string           `json:"algorithm,omitempty"`
	KeySize            int              `json:"keySize,omitempty"`
	Country            string           `json:"country"`
	Province           string           `json:"province"`
	City               string           `json:"city"`
	Organization       string           `json:"organization"`
	OrganizationalUnit string           `json:"organizationalUnit"`
	CommonName         string           `json:"commonName"`
	Expiry             int              `json:"expiry"`
	SubjectAltNames    []SubjectAltName `json:"subjectAltNames,omitempty"`
	Comment            string           `json:"comment,omitempty"`
}

// ImportCADTO is used to import a CA certificate
type ImportCADTO struct {
	Certificate string `json:"certificate"`
	PrivKey     string `json:"privkey"`
	Comment     string `json:"comment"`
}

// CABindingDTO represents a CA-User binding
type CABindingDTO struct {
	CaUUID   string `json:"caUuid"`
	Username string `json:"username"`
}

// CertAnalysisDTO represents certificate analysis result
type CertAnalysisDTO struct {
	Subject      string            `json:"subject"`
	Issuer       string            `json:"issuer"`
	NotBefore    string            `json:"notBefore"`
	NotAfter     string            `json:"notAfter"`
	SerialNumber string            `json:"serialNumber"`
	PublicKey    PublicKeyDTO      `json:"publicKey"`
	Extensions   map[string]string `json:"extensions"`
}

// ECPointW represents an ECC public key point (JCE format)
type ECPointW struct {
	AffineX string `json:"affineX"`
	AffineY string `json:"affineY"`
}

// ECPointQ represents an ECC public key point (BouncyCastle format)
type ECPointQ struct {
	X                string `json:"x"`
	Y                string `json:"y"`
	CoordinateSystem int    `json:"coordinateSystem"`
}

// Ed25519Point represents an Ed25519 public key point
type Ed25519Point struct {
	Y    string `json:"y"`
	XOdd bool   `json:"xodd"`
}

// PublicKeyDTO represents public key information.
// The Params field is json.RawMessage because its JSON type differs by key algorithm:
// RSA → null, ECC → a JSON object (ECParameterSpec), Ed25519 → a JSON object (NamedParameterSpec).
type PublicKeyDTO struct {
	// RSA-specific fields
	Modulus  string `json:"modulus"`
	Exponent string `json:"publicExponent"`
	// ECC-specific fields
	W *ECPointW `json:"w"`
	Q *ECPointQ `json:"q"`
	// Ed25519-specific fields
	Point *Ed25519Point `json:"point"`
	// Common fields
	Encoded   string          `json:"encoded"`
	Algorithm string          `json:"algorithm"`
	Format    string          `json:"format"`
	Params    json.RawMessage `json:"params"`
}
