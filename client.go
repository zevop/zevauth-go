package zevauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is this library's version, sent in the User-Agent.
const Version = "0.1.0"

const userAgent = "zevauth-go/" + Version

const (
	defaultTimeout    = 15 * time.Second
	defaultMaxRetries = 2
	maxRetryAfter     = 10 * time.Second
	maxBackoff        = 4 * time.Second
)

// Client error codes produced before or around a request.
const (
	CodeMissingSecretKey = "missing_secret_key"
	CodeWrongKeyType     = "wrong_key_type"
	CodeRequestFailed    = "request_failed"
	CodeNetworkError     = "network_error"
)

// ClientOptions configure NewClient.
type ClientOptions struct {
	// APIURL defaults to DefaultAPIURL.
	APIURL string
	// Timeout per attempt. Defaults to 15 seconds.
	Timeout time.Duration
	// MaxRetries for retryable failures. Defaults to 2. Use -1 for none.
	MaxRetries int
	// HTTPClient sends requests. Defaults to http.DefaultClient's
	// transport with no client-level timeout (Timeout applies per attempt).
	HTTPClient *http.Client
	// Sleep waits between retries. Tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client calls the ZevAuth backend API with a secret key. Safe for
// concurrent use.
type Client struct {
	secret     string
	apiURL     string
	timeout    time.Duration
	maxRetries int
	http       *http.Client
	sleep      func(ctx context.Context, d time.Duration) error

	Users         *UsersService
	Organizations *OrganizationsService
}

// NewClient needs a secret key (sk_test_… or sk_live_…). A publishable
// key is refused: it cannot call the backend API, and a server holding
// one usually means the keys were swapped.
func NewClient(secretKey string, opts ClientOptions) (*Client, error) {
	if secretKey == "" {
		return nil, &APIError{Code: CodeMissingSecretKey, Message: "a secret key (sk_…) is required"}
	}
	if strings.HasPrefix(secretKey, "pk_") {
		return nil, &APIError{Code: CodeWrongKeyType, Message: "that is a publishable key; the backend API needs your secret key (sk_…)"}
	}
	c := &Client{
		secret:     secretKey,
		apiURL:     strings.TrimRight(opts.APIURL, "/"),
		timeout:    opts.Timeout,
		maxRetries: opts.MaxRetries,
		http:       opts.HTTPClient,
		sleep:      opts.Sleep,
	}
	if c.apiURL == "" {
		c.apiURL = DefaultAPIURL
	}
	if c.timeout == 0 {
		c.timeout = defaultTimeout
	}
	switch {
	case c.maxRetries == 0:
		c.maxRetries = defaultMaxRetries
	case c.maxRetries < 0:
		c.maxRetries = 0
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	if c.sleep == nil {
		c.sleep = sleepContext
	}
	c.Users = &UsersService{c: c}
	c.Organizations = &OrganizationsService{c: c}
	return c, nil
}

// do sends one API call with the retry rule (contract §3.5): retry 429,
// 502, 503, 504 and transport failures; never another 4xx, never a 500.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("zevauth: encoding request: %w", err)
		}
	}
	target := c.apiURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	for attempt := 0; ; attempt++ {
		retryAfter, err := c.attempt(ctx, method, target, payload, out)
		if err == nil {
			return nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || !retryable(apiErr.Status) || attempt >= c.maxRetries || ctx.Err() != nil {
			return err
		}
		wait := backoff(attempt)
		if retryAfter > 0 {
			wait = min(retryAfter, maxRetryAfter)
		}
		if serr := c.sleep(ctx, wait); serr != nil {
			return err
		}
	}
}

func (c *Client) attempt(ctx context.Context, method, target string, payload []byte, out any) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, fmt.Errorf("zevauth: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.http.Do(req)
	if err != nil {
		return 0, &APIError{Code: CodeNetworkError, Status: 0, Message: err.Error(), Err: err}
	}
	defer res.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(res.Body, 10<<20))

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		if readErr != nil {
			return 0, &APIError{Code: CodeNetworkError, Status: 0, Message: readErr.Error(), Err: readErr}
		}
		if out != nil && len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return 0, fmt.Errorf("zevauth: decoding response: %w", err)
			}
		}
		return 0, nil
	}
	return parseRetryAfter(res.Header.Get("Retry-After")), apiErrorFrom(res.StatusCode, res.Header, data)
}

// apiErrorFrom reads the API's error envelope. A body that is not JSON,
// or has no code, is request_failed.
func apiErrorFrom(status int, header http.Header, data []byte) *APIError {
	e := &APIError{Code: CodeRequestFailed, Status: status, RequestID: header.Get("X-Request-Id")}
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &envelope) == nil && envelope.Error.Code != "" {
		e.Code = envelope.Error.Code
		e.Message = envelope.Error.Message
	}
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	return e
}

func retryable(status int) bool {
	switch status {
	case 0, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func backoff(attempt int) time.Duration {
	d := 200 * time.Millisecond << attempt
	if d > maxBackoff || d <= 0 {
		return maxBackoff
	}
	return d
}

func parseRetryAfter(v string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || seconds < 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func escape(id string) string { return url.PathEscape(id) }
