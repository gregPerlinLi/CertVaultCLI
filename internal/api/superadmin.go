package api

import (
	"fmt"
	"net/http"
)

// SuperAdminListAllSessions returns all login records (superadmin)
func (c *Client) SuperAdminListAllSessions(status string, page, limit int) (*PageDTO[LoginRecordDTO], error) {
	path := fmt.Sprintf("/api/v1/superadmin/user/session?page=%d&limit=%d", page, limit)
	if status != "" {
		path += "&status=" + status
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

// SuperAdminGetUserSessions returns a specific user's login records (superadmin)
func (c *Client) SuperAdminGetUserSessions(username, status string, page, limit int) (*PageDTO[LoginRecordDTO], error) {
	path := fmt.Sprintf("/api/v1/superadmin/user/session/%s?page=%d&limit=%d", username, page, limit)
	if status != "" {
		path += "&status=" + status
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

// SuperAdminForceLogoutUser force-logouts a user (superadmin)
func (c *Client) SuperAdminForceLogoutUser(username string) error {
	resp, err := c.do("DELETE", fmt.Sprintf("/api/v1/superadmin/user/%s/logout", username), nil)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// SuperAdminCreateUser creates a user (superadmin)
func (c *Client) SuperAdminCreateUser(dto CreateUserDTO) error {
	resp, err := c.do(http.MethodPost, "/api/v1/superadmin/user", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// SuperAdminUpdateUser updates a user's info (superadmin)
func (c *Client) SuperAdminUpdateUser(username string, dto UpdateUserProfileDTO) error {
	resp, err := c.do(http.MethodPatch, fmt.Sprintf("/api/v1/superadmin/user/%s", username), dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// SuperAdminUpdateUserRole updates a user's role (superadmin)
func (c *Client) SuperAdminUpdateUserRole(username string, role int32) error {
	dto := UpdateRoleDTO{Username: username, Role: role}
	resp, err := c.do(http.MethodPatch, "/api/v1/superadmin/user/role", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// SuperAdminDeleteUser deletes a user (superadmin)
func (c *Client) SuperAdminDeleteUser(username string) error {
	resp, err := c.do("DELETE", fmt.Sprintf("/api/v1/superadmin/user/%s", username), nil)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// SuperAdminCountCAs counts CAs (superadmin)
func (c *Client) SuperAdminCountCAs(condition string) (int64, error) {
	path := "/api/v1/superadmin/cert/ca/count"
	if condition != "" {
		path += "?condition=" + condition
	}
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	return parseResponse[int64](resp)
}

// SuperAdminCountSSLCerts counts SSL certificates (superadmin)
func (c *Client) SuperAdminCountSSLCerts() (int64, error) {
	resp, err := c.do(http.MethodGet, "/api/v1/superadmin/cert/ssl/count", nil)
	if err != nil {
		return 0, err
	}
	return parseResponse[int64](resp)
}
