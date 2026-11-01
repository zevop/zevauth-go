package zevauth

import "fmt"

// Verification error codes (contract §1.4). Every one means "this request
// is not signed in"; GetAuth turns them into a signed-out Auth.
const (
	CodeMalformedToken       = "malformed_token"
	CodeUnsupportedAlgorithm = "unsupported_algorithm"
	CodeUnknownKey           = "unknown_key"
	CodeInvalidSignature     = "invalid_signature"
	CodeInvalidIssuer        = "invalid_issuer"
	CodeInvalidAudience      = "invalid_audience"
	CodeTokenExpired         = "token_expired"
	CodeTokenNotYetValid     = "token_not_yet_valid"
	CodeJWKSUnavailable      = "jwks_unavailable"
)

// Sentinels for errors.Is. A *VerifyError matches the sentinel with the
// same code, so callers can write errors.Is(err, zevauth.ErrTokenExpired).
var (
	ErrMalformedToken       = &VerifyError{Code: CodeMalformedToken}
	ErrUnsupportedAlgorithm = &VerifyError{Code: CodeUnsupportedAlgorithm}
	ErrUnknownKey           = &VerifyError{Code: CodeUnknownKey}
	ErrInvalidSignature     = &VerifyError{Code: CodeInvalidSignature}
	ErrInvalidIssuer        = &VerifyError{Code: CodeInvalidIssuer}
	ErrInvalidAudience      = &VerifyError{Code: CodeInvalidAudience}
	ErrTokenExpired         = &VerifyError{Code: CodeTokenExpired}
	ErrTokenNotYetValid     = &VerifyError{Code: CodeTokenNotYetValid}
	ErrJWKSUnavailable      = &VerifyError{Code: CodeJWKSUnavailable}
)

// VerifyError is returned by Verifier.Verify.
type VerifyError struct {
	Code    string
	Message string
	Err     error // the underlying cause, when there is one
}

func (e *VerifyError) Error() string {
	if e.Message == "" {
		return "zevauth: " + e.Code
	}
	return fmt.Sprintf("zevauth: %s: %s", e.Code, e.Message)
}

func (e *VerifyError) Unwrap() error { return e.Err }

// Is matches any *VerifyError with the same code.
func (e *VerifyError) Is(target error) bool {
	t, ok := target.(*VerifyError)
	return ok && t.Code == e.Code
}

func verifyErr(code, message string) *VerifyError {
	return &VerifyError{Code: code, Message: message}
}

// APIError is returned by the backend API client (contract §3.4).
type APIError struct {
	Code      string
	Status    int // 0 for a transport failure
	Message   string
	RequestID string // from the x-request-id response header, when sent
	Err       error  // the transport error, for network_error
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("zevauth: %s (%d): %s", e.Code, e.Status, e.Message)
	if e.RequestID != "" {
		s += " [request " + e.RequestID + "]"
	}
	return s
}

func (e *APIError) Unwrap() error { return e.Err }

// Webhook verification error codes (contract §4).
const (
	CodeWebhookMalformedSignature  = "webhook_malformed_signature"
	CodeWebhookTimestampOutOfRange = "webhook_timestamp_out_of_range"
	CodeWebhookSignatureMismatch   = "webhook_signature_mismatch"
)

// WebhookError is returned by VerifyWebhook.
type WebhookError struct {
	Code    string
	Message string
}

func (e *WebhookError) Error() string { return "zevauth: " + e.Code + ": " + e.Message }

// Is matches any *WebhookError with the same code.
func (e *WebhookError) Is(target error) bool {
	t, ok := target.(*WebhookError)
	return ok && t.Code == e.Code
}

var (
	ErrWebhookMalformedSignature  = &WebhookError{Code: CodeWebhookMalformedSignature}
	ErrWebhookTimestampOutOfRange = &WebhookError{Code: CodeWebhookTimestampOutOfRange}
	ErrWebhookSignatureMismatch   = &WebhookError{Code: CodeWebhookSignatureMismatch}
)
