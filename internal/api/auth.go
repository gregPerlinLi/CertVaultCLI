package api

import (
	"fmt"
	"net/http"
)

// Login logs in with username and password
func (c *Client) Login(username, password string) (*UserProfileDTO, error) {
	body := map[string]string{
		"username": username,
		"password": password,
	}
	resp, err := c.do(http.MethodPost, "/api/v1/auth/login", body)
	if err != nil {
		return nil, err
	}

	// Extract JSESSIONID before parsing body
	var jsessionID string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "JSESSIONID" {
			jsessionID = cookie.Value
			break
		}
	}

	profile, err := parseResponse[UserProfileDTO](resp)
	if err != nil {
		return nil, err
	}

	if jsessionID == "" {
		return nil, fmt.Errorf("login succeeded but no session cookie received")
	}

	if err := c.SetSession(jsessionID); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

	return &profile, nil
}

// Logout logs out the current session
func (c *Client) Logout() error {
	resp, err := c.do("DELETE", "/api/v1/auth/logout", nil)
	if err != nil {
		return err
	}
	if err := parseEmptyResponse(resp); err != nil {
		return err
	}
	return c.ClearSession()
}
