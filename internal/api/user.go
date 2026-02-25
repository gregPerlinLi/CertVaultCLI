package api

import (
	"fmt"
	"net/http"
)

// GetProfile returns the current user's profile
func (c *Client) GetProfile() (*UserProfileDTO, error) {
	resp, err := c.do(http.MethodGet, "/api/v1/user/profile", nil)
	if err != nil {
		return nil, err
	}
	profile, err := parseResponse[UserProfileDTO](resp)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

// UpdateProfile updates the current user's profile
func (c *Client) UpdateProfile(dto UpdateUserProfileDTO) error {
	resp, err := c.do(http.MethodPatch, "/api/v1/user/profile", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// GetSessions returns a paginated list of the user's login sessions
func (c *Client) GetSessions(status string, page, limit int, orderBy string, isAsc bool) (*PageDTO[LoginRecordDTO], error) {
	path := fmt.Sprintf("/api/v1/user/session?page=%d&limit=%d&isAsc=%v", page, limit, isAsc)
	if status != "" {
		path += "&status=" + status
	}
	if orderBy != "" {
		path += "&orderBy=" + orderBy
	}
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	result, err := parseResponse[PageDTO[LoginRecordDTO]](resp)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// LogoutSession force-logouts a specific session
func (c *Client) LogoutSession(uuid string) error {
	resp, err := c.do("DELETE", fmt.Sprintf("/api/v1/user/session/%s/logout", uuid), nil)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// LogoutAllSessions force-logouts all user sessions
func (c *Client) LogoutAllSessions() error {
	resp, err := c.do("DELETE", "/api/v1/user/logout", nil)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// ListUserCAs returns the user's bound CA list
func (c *Client) ListUserCAs(keyword string, page, limit int) (*PageDTO[CaInfoDTO], error) {
	path := fmt.Sprintf("/api/v1/user/cert/ca?page=%d&limit=%d", page, limit)
	if keyword != "" {
		path += "&keyword=" + keyword
	}
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	result, err := parseResponse[PageDTO[CaInfoDTO]](resp)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUserCACert returns the CA certificate content (base64 encoded)
func (c *Client) GetUserCACert(uuid string, isChain, needRootCa bool) (string, error) {
	path := fmt.Sprintf("/api/v1/user/cert/ca/%s/cer?isChain=%v&needRootCa=%v", uuid, isChain, needRootCa)
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	return parseResponse[string](resp)
}

// ListUserSSLCerts returns the user's SSL certificate list
func (c *Client) ListUserSSLCerts(keyword string, page, limit int) (*PageDTO[CertInfoDTO], error) {
	path := fmt.Sprintf("/api/v1/user/cert/ssl?page=%d&limit=%d", page, limit)
	if keyword != "" {
		path += "&keyword=" + keyword
	}
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	result, err := parseResponse[PageDTO[CertInfoDTO]](resp)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUserSSLCert returns the SSL certificate content (base64 encoded)
func (c *Client) GetUserSSLCert(uuid string, isChain, needRootCa bool) (string, error) {
	path := fmt.Sprintf("/api/v1/user/cert/ssl/%s/cer?isChain=%v&needRootCa=%v", uuid, isChain, needRootCa)
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	return parseResponse[string](resp)
}

// GetUserSSLPrivKey returns the SSL certificate private key (base64 encoded)
func (c *Client) GetUserSSLPrivKey(uuid, password string) (string, error) {
	body := map[string]string{"password": password}
	resp, err := c.do(http.MethodPost, fmt.Sprintf("/api/v1/user/cert/ssl/%s/privkey", uuid), body)
	if err != nil {
		return "", err
	}
	return parseResponse[string](resp)
}

// UpdateSSLCertComment updates the comment on an SSL certificate
func (c *Client) UpdateSSLCertComment(uuid, comment string) error {
	body := map[string]string{"comment": comment}
	resp, err := c.do(http.MethodPatch, fmt.Sprintf("/api/v1/user/cert/ssl/%s/comment", uuid), body)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AnalyzeCertificate analyzes a PEM certificate (base64 encoded input)
func (c *Client) AnalyzeCertificate(certBase64 string) (*CertAnalysisDTO, error) {
	body := map[string]string{"cert": certBase64}
	resp, err := c.do(http.MethodPost, "/api/v1/user/cert/analyze", body)
	if err != nil {
		return nil, err
	}
	result, err := parseResponse[CertAnalysisDTO](resp)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
