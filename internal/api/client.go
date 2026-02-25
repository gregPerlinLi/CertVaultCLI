package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gregPerlinLi/CertVaultCLI/internal/config"
)

// Client is the HTTP client for the CertVault API
type Client struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewClient creates a new API client
func NewClient() (*Client, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{},
	}, nil
}

// BaseURL returns the base URL
func (c *Client) BaseURL() string {
	return c.cfg.BaseURL
}

// SetBaseURL sets the base URL and saves config
func (c *Client) SetBaseURL(url string) error {
	c.cfg.BaseURL = url
	return config.Save(c.cfg)
}

// SetSession saves a session ID
func (c *Client) SetSession(jsessionID string) error {
	c.cfg.JSessionID = jsessionID
	return config.Save(c.cfg)
}

// ClearSession clears the session ID
func (c *Client) ClearSession() error {
	c.cfg.JSessionID = ""
	return config.Save(c.cfg)
}

// IsLoggedIn returns true if we have a session
func (c *Client) IsLoggedIn() bool {
	return c.cfg.JSessionID != ""
}

// do performs an HTTP request with session cookie
func (c *Client) do(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.cfg.BaseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "CertVaultCLI/2.0.0 (CLI)")
	if c.cfg.JSessionID != "" {
		req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: c.cfg.JSessionID})
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	return resp, nil
}

// parseResponse parses a JSON response body into the result
func parseResponse[T any](resp *http.Response) (T, error) {
	defer resp.Body.Close()
	var result ResultVO[T]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		var zero T
		return zero, fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Code != 200 {
		var zero T
		return zero, fmt.Errorf("%s (code %d)", result.Msg, result.Code)
	}
	return result.Data, nil
}

// parseEmptyResponse parses a response that returns no data
func parseEmptyResponse(resp *http.Response) error {
	defer resp.Body.Close()
	var result ResultVO[json.RawMessage]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Code != 200 {
		return fmt.Errorf("%s (code %d)", result.Msg, result.Code)
	}
	return nil
}
