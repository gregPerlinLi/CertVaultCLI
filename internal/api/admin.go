package api

import (
	"fmt"
	"net/http"
)

// AdminListUsers returns a paginated list of all users (admin)
func (c *Client) AdminListUsers(keyword string, page, limit int) (*PageDTO[UserProfileDTO], error) {
	path := fmt.Sprintf("/api/v1/admin/users?page=%d&limit=%d", page, limit)
	if keyword != "" {
		path += "&keyword=" + keyword
	}
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	result, err := parseResponse[PageDTO[UserProfileDTO]](resp)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// AdminListCAs returns a paginated list of all CAs (admin)
func (c *Client) AdminListCAs(keyword string, page, limit int) (*PageDTO[CaInfoDTO], error) {
	path := fmt.Sprintf("/api/v1/admin/cert/ca?page=%d&limit=%d", page, limit)
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

// AdminGetCACert returns a CA certificate (admin)
func (c *Client) AdminGetCACert(uuid string, isChain, needRootCa bool) (string, error) {
	path := fmt.Sprintf("/api/v1/admin/cert/ca/%s/cer?isChain=%v&needRootCa=%v", uuid, isChain, needRootCa)
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	return parseResponse[string](resp)
}

// AdminGetCAPrivKey returns a CA private key (admin, requires password)
func (c *Client) AdminGetCAPrivKey(uuid, password string) (string, error) {
	body := map[string]string{"password": password}
	resp, err := c.do(http.MethodPost, fmt.Sprintf("/api/v1/admin/cert/ca/%s/privkey", uuid), body)
	if err != nil {
		return "", err
	}
	return parseResponse[string](resp)
}

// AdminUpdateCAComment updates a CA's comment (admin)
func (c *Client) AdminUpdateCAComment(uuid, comment string) error {
	body := map[string]string{"comment": comment}
	resp, err := c.do(http.MethodPatch, fmt.Sprintf("/api/v1/admin/cert/ca/%s/comment", uuid), body)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminToggleCAAvailable toggles CA availability (admin)
func (c *Client) AdminToggleCAAvailable(uuid string) error {
	resp, err := c.do(http.MethodPatch, fmt.Sprintf("/api/v1/admin/cert/ca/%s/available", uuid), nil)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminImportCA imports a CA certificate (admin)
func (c *Client) AdminImportCA(dto ImportCADTO) error {
	resp, err := c.do(http.MethodPost, "/api/v1/admin/cert/ca/import", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminBindUsersToCA binds users to a CA (admin)
func (c *Client) AdminBindUsersToCA(caUUID string, usernames []string) error {
	body := map[string][]string{"usernames": usernames}
	resp, err := c.do(http.MethodPost, fmt.Sprintf("/api/v1/admin/cert/ca/%s/bind", caUUID), body)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminUnbindUsersFromCA unbinds users from a CA (admin)
func (c *Client) AdminUnbindUsersFromCA(caUUID string, usernames []string) error {
	body := map[string][]string{"usernames": usernames}
	resp, err := c.do("DELETE", fmt.Sprintf("/api/v1/admin/cert/ca/%s/bind", caUUID), body)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminGetCABoundUsers returns users bound to a CA (admin)
func (c *Client) AdminGetCABoundUsers(caUUID string, page, limit int) (*PageDTO[UserProfileDTO], error) {
	path := fmt.Sprintf("/api/v1/admin/cert/ca/%s/bind?page=%d&limit=%d", caUUID, page, limit)
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	result, err := parseResponse[PageDTO[UserProfileDTO]](resp)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// AdminGetCAUnboundUsers returns users NOT bound to a CA (admin)
func (c *Client) AdminGetCAUnboundUsers(caUUID string, page, limit int) (*PageDTO[UserProfileDTO], error) {
	path := fmt.Sprintf("/api/v1/admin/cert/ca/%s/bind/not?page=%d&limit=%d", caUUID, page, limit)
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	result, err := parseResponse[PageDTO[UserProfileDTO]](resp)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// AdminCreateRootCA creates a root CA (admin)
func (c *Client) AdminCreateRootCA(dto CreateRootCADTO) error {
	resp, err := c.do(http.MethodPost, "/api/v1/admin/cert/ca/create/root", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminCreateIntCA creates an intermediate CA (admin)
func (c *Client) AdminCreateIntCA(dto CreateIntCADTO) error {
	resp, err := c.do(http.MethodPost, "/api/v1/admin/cert/ca/create/int", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminIssueSSLCert issues an SSL certificate (admin)
func (c *Client) AdminIssueSSLCert(dto IssueSSLCertDTO) error {
	resp, err := c.do(http.MethodPost, "/api/v1/admin/cert/ssl/issue", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminRenewSSLCert renews an SSL certificate (admin)
func (c *Client) AdminRenewSSLCert(uuid string) error {
	resp, err := c.do(http.MethodPost, fmt.Sprintf("/api/v1/admin/cert/ssl/%s/renew", uuid), nil)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminDeleteSSLCert deletes an SSL certificate (admin)
func (c *Client) AdminDeleteSSLCert(uuid string) error {
	resp, err := c.do("DELETE", fmt.Sprintf("/api/v1/admin/cert/ssl/%s", uuid), nil)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}
