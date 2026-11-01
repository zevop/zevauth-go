package zevauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultAPIURL is where ZevAuth's API lives unless configured otherwise.
const DefaultAPIURL = "https://api.zevauth.net"

const (
	defaultClockSkew       = 5 * time.Second
	defaultKeyCacheTTL     = 10 * time.Minute
	defaultRefetchCooldown = 30 * time.Second
)

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// EnvironmentID is required: env_test_… or env_live_…. Tokens for any
	// other environment are refused (invalid_audience).
	EnvironmentID string

	// APIURL defaults to DefaultAPIURL. The issuer is read from the
	// discovery document under it, never built from it.
	APIURL string

	// Issuer and JWKS supply a local key set instead of fetching one, for
	// tests and air-gapped servers. Both must be set together.
	Issuer string
	JWKS   []byte

	// HTTPClient fetches discovery and keys. Defaults to a client with a
	// 10 second timeout.
	HTTPClient *http.Client

	// Now is the clock. Defaults to time.Now; tests fix it.
	Now func() time.Time

	// ClockSkew tolerated on exp and nbf. Defaults to 5 seconds.
	ClockSkew time.Duration

	// KeyCacheTTL bounds how long a fetched key set is trusted. Defaults
	// to (and is capped at) 10 minutes.
	KeyCacheTTL time.Duration

	// RefetchCooldown limits refetches caused by unknown key ids, so a
	// token with a made-up kid cannot make every request fetch. Defaults
	// to 30 seconds.
	RefetchCooldown time.Duration
}

// Verifier checks ZevAuth session tokens. It is safe for concurrent use;
// create one per environment and share it.
type Verifier struct {
	cfg VerifierConfig

	mu          sync.Mutex
	issuer      string
	jwksURI     string
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastRefetch time.Time
}

// NewVerifier validates the configuration. It does not fetch anything;
// keys are fetched on first use.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.EnvironmentID == "" {
		return nil, errors.New("zevauth: EnvironmentID is required")
	}
	if (cfg.Issuer == "") != (cfg.JWKS == nil) {
		return nil, errors.New("zevauth: Issuer and JWKS must be set together")
	}
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}
	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	if cfg.KeyCacheTTL <= 0 || cfg.KeyCacheTTL > defaultKeyCacheTTL {
		cfg.KeyCacheTTL = defaultKeyCacheTTL
	}
	if cfg.RefetchCooldown == 0 {
		cfg.RefetchCooldown = defaultRefetchCooldown
	}

	v := &Verifier{cfg: cfg}
	if cfg.JWKS != nil {
		keys, err := parseJWKS(cfg.JWKS)
		if err != nil {
			return nil, fmt.Errorf("zevauth: local JWKS: %w", err)
		}
		v.issuer = cfg.Issuer
		v.keys = keys
	}
	return v, nil
}

// EnvironmentID is the environment this verifier accepts tokens for.
func (v *Verifier) EnvironmentID() string { return v.cfg.EnvironmentID }

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// Verify checks a token in the contract's order (§1.3) and returns its
// claims, or a *VerifyError naming why it was refused.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, verifyErr(CodeMalformedToken, "not a JWT")
	}
	var header jwtHeader
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, verifyErr(CodeMalformedToken, "unreadable header")
	}
	var raw map[string]any
	if err := decodeSegment(parts[1], &raw); err != nil {
		return nil, verifyErr(CodeMalformedToken, "unreadable payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, verifyErr(CodeMalformedToken, "unreadable signature")
	}

	// Never let the token choose the algorithm: refuse before any key is
	// looked at, so none and HS256 key confusion never reach a verifier.
	if header.Alg != "RS256" {
		return nil, verifyErr(CodeUnsupportedAlgorithm, fmt.Sprintf("alg %q", header.Alg))
	}

	key, issuer, err := v.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return nil, verifyErr(CodeInvalidSignature, "")
	}

	claims, err := claimsFrom(raw)
	if err != nil {
		return nil, err
	}
	if claims.Issuer != issuer {
		return nil, verifyErr(CodeInvalidIssuer, claims.Issuer)
	}
	if !claims.audienceIs(v.cfg.EnvironmentID) {
		return nil, verifyErr(CodeInvalidAudience, "")
	}

	now := v.cfg.Now()
	if claims.ExpiresAt != 0 && now.After(time.Unix(claims.ExpiresAt, 0).Add(v.cfg.ClockSkew)) {
		return nil, verifyErr(CodeTokenExpired, "")
	}
	if claims.NotBefore != 0 && now.Before(time.Unix(claims.NotBefore, 0).Add(-v.cfg.ClockSkew)) {
		return nil, verifyErr(CodeTokenNotYetValid, "")
	}
	return claims, nil
}

// key returns the key for kid, applying the rotation rule: one refetch
// for an unknown kid, at most once per cooldown.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	local := v.cfg.JWKS != nil
	if !local && (v.keys == nil || v.cfg.Now().Sub(v.fetchedAt) > v.cfg.KeyCacheTTL) {
		if err := v.fetchLocked(ctx); err != nil {
			return nil, "", err
		}
	}
	if k, ok := v.keys[kid]; ok {
		return k, v.issuer, nil
	}
	if !local && v.cfg.Now().Sub(v.lastRefetch) >= v.cfg.RefetchCooldown {
		v.lastRefetch = v.cfg.Now()
		if err := v.fetchLocked(ctx); err != nil {
			return nil, "", err
		}
		if k, ok := v.keys[kid]; ok {
			return k, v.issuer, nil
		}
	}
	return nil, "", verifyErr(CodeUnknownKey, kid)
}

// fetchLocked loads discovery (once) and the key set. Holding the lock
// while fetching is what makes concurrent first requests share one fetch.
func (v *Verifier) fetchLocked(ctx context.Context) error {
	if v.jwksURI == "" {
		var doc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		u := v.cfg.APIURL + "/v1/" + url.PathEscape(v.cfg.EnvironmentID) + "/.well-known/openid-configuration"
		if err := v.getJSON(ctx, u, &doc); err != nil {
			return err
		}
		if doc.Issuer == "" || doc.JWKSURI == "" {
			return &VerifyError{Code: CodeJWKSUnavailable, Message: "discovery document is missing issuer or jwks_uri"}
		}
		v.issuer, v.jwksURI = doc.Issuer, doc.JWKSURI
	}
	var body json.RawMessage
	if err := v.getJSON(ctx, v.jwksURI, &body); err != nil {
		return err
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return &VerifyError{Code: CodeJWKSUnavailable, Message: "unreadable key set", Err: err}
	}
	v.keys = keys
	v.fetchedAt = v.cfg.Now()
	return nil
}

func (v *Verifier) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return &VerifyError{Code: CodeJWKSUnavailable, Message: err.Error(), Err: err}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	res, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return &VerifyError{Code: CodeJWKSUnavailable, Message: err.Error(), Err: err}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return &VerifyError{Code: CodeJWKSUnavailable, Message: fmt.Sprintf("%s answered %d", u, res.StatusCode)}
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return &VerifyError{Code: CodeJWKSUnavailable, Message: err.Error(), Err: err}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &VerifyError{Code: CodeJWKSUnavailable, Message: "not JSON", Err: err}
	}
	return nil
}

func decodeSegment(segment string, out any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// parseJWKS keeps only RSA signing keys meant for RS256.
func parseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(e) > 4 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return keys, nil
}
