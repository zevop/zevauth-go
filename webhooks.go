package zevauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Webhook delivery headers (contract §4).
const (
	WebhookSignatureHeader  = "zevauth-signature"
	WebhookEventTypeHeader  = "zevauth-event-type"
	WebhookDeliveryIDHeader = "zevauth-delivery-id"
	WebhookAttemptHeader    = "zevauth-attempt"
)

const defaultWebhookTolerance = 300 * time.Second

// WebhookOptions are optional settings for VerifyWebhook.
type WebhookOptions struct {
	// Tolerance for the signature's timestamp. Defaults to 300 seconds.
	Tolerance time.Duration
	// Now is the clock. Defaults to time.Now.
	Now func() time.Time
}

// VerifyWebhook checks a delivery's zevauth-signature header against the
// raw request body. Pass the exact bytes received: a body that was parsed
// and re-encoded fails, correctly. Returns a *WebhookError on refusal.
func VerifyWebhook(payload []byte, signature, secret string, opts WebhookOptions) error {
	tolerance := opts.Tolerance
	if tolerance == 0 {
		tolerance = defaultWebhookTolerance
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	var timestamp, v1 string
	for _, part := range strings.Split(signature, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "t":
			timestamp = strings.TrimSpace(value)
		case "v1":
			v1 = strings.TrimSpace(value)
		}
	}
	t, err := strconv.ParseInt(timestamp, 10, 64)
	if timestamp == "" || v1 == "" || err != nil {
		return &WebhookError{Code: CodeWebhookMalformedSignature, Message: "expected t=<seconds>,v1=<hex>"}
	}

	age := now().Unix() - t
	if age < 0 {
		age = -age
	}
	if time.Duration(age)*time.Second > tolerance {
		return &WebhookError{Code: CodeWebhookTimestampOutOfRange, Message: "the signature timestamp is outside the tolerance"}
	}

	// The key is the whole secret, whsec_ prefix included.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	// Exact and constant-time: no case folding, no early exit.
	if subtle.ConstantTimeCompare([]byte(expected), []byte(v1)) != 1 {
		return &WebhookError{Code: CodeWebhookSignatureMismatch, Message: "the signature does not match the body"}
	}
	return nil
}

// WebhookEvent is a verified delivery's body.
type WebhookEvent struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	CreatedAt string          `json:"createdAt"`
	Data      json.RawMessage `json:"data"`
}

// ConstructWebhookEvent verifies the delivery, then parses it. Use the
// event ID (or the zevauth-delivery-id header) to stay idempotent:
// deliveries are at-least-once.
func ConstructWebhookEvent(payload []byte, signature, secret string, opts WebhookOptions) (*WebhookEvent, error) {
	if err := VerifyWebhook(payload, signature, secret, opts); err != nil {
		return nil, err
	}
	var event WebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, &WebhookError{Code: CodeWebhookMalformedSignature, Message: "the signed body is not a JSON event"}
	}
	return &event, nil
}
