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
// AdminBindUsersToCA binds multiple users to a CA (admin)
func (c *Client) AdminBindUsersToCA(caUUID string, usernames []string) error {
	bindings := make([]CABindingDTO, len(usernames))
	for i, u := range usernames {
		bindings[i] = CABindingDTO{CaUUID: caUUID, Username: u}
	}
	resp, err := c.do(http.MethodPost, "/api/v1/admin/cert/ca/binds/create", bindings)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminUnbindUsersFromCA unbinds multiple users from a CA (admin)
func (c *Client) AdminUnbindUsersFromCA(caUUID string, usernames []string) error {
	bindings := make([]CABindingDTO, len(usernames))
	for i, u := range usernames {
		bindings[i] = CABindingDTO{CaUUID: caUUID, Username: u}
	}
	resp, err := c.do(http.MethodPost, "/api/v1/admin/cert/ca/binds/delete", bindings)
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
func (c *Client) AdminCreateRootCA(dto RequestCertDTO) error {
	resp, err := c.do(http.MethodPost, "/api/v1/admin/cert/ca", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminCreateIntCA creates an intermediate CA (admin)
func (c *Client) AdminCreateIntCA(dto RequestCertDTO) error {
	resp, err := c.do(http.MethodPost, "/api/v1/admin/cert/ca", dto)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminRenewCA renews a CA certificate (admin)
func (c *Client) AdminRenewCA(uuid string, expiry int) error {
	body := map[string]int{"expiry": expiry}
	resp, err := c.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/cert/ca/%s", uuid), body)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}

// AdminDeleteCA deletes a CA certificate (admin)
func (c *Client) AdminDeleteCA(uuid string) error {
	resp, err := c.do(http.MethodDelete, fmt.Sprintf("/api/v1/admin/cert/ca/%s", uuid), nil)
	if err != nil {
		return err
	}
	return parseEmptyResponse(resp)
}
