package zevauth

// Runs the shared conformance fixtures (testdata/, synced from
// https://github.com/zevop/zevauth-sdk/tree/main/spec) with the clock
// fixed to the fixtures' "now".

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func load(t *testing.T, name string, out any) {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respond(status int, body []byte, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: header}
}

type tokenFixtures struct {
	Now              int64  `json:"now"`
	EnvironmentID    string `json:"environmentId"`
	Issuer           string `json:"issuer"`
	ClockSkewSeconds int    `json:"clockSkewSeconds"`
	Cases            []struct {
		Name             string `json:"name"`
		Token            string `json:"token"`
		JWKS             string `json:"jwks"`
		JWKSAfterRefetch string `json:"jwksAfterRefetch"`
		Expect           struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		} `json:"expect"`
		Auth *struct {
			IsSignedIn       bool     `json:"isSignedIn"`
			UserID           *string  `json:"userId"`
			SessionID        *string  `json:"sessionId"`
			OrganizationID   *string  `json:"organizationId"`
			OrganizationRole *string  `json:"organizationRole"`
			PendingTasks     []string `json:"pendingTasks"`
			IsMFAVerified    bool     `json:"isMfaVerified"`
		} `json:"auth"`
		Has []struct {
			Check  HasCheck `json:"check"`
			Result bool     `json:"result"`
		} `json:"has"`
		RequireAuth []struct {
			Options struct {
				AllowPendingTasks bool `json:"allowPendingTasks"`
				RequireMFA        bool `json:"requireMfa"`
			} `json:"options"`
			Result struct {
				OK     bool   `json:"ok"`
				Status int    `json:"status"`
				Code   string `json:"code"`
			} `json:"result"`
		} `json:"requireAuth"`
	} `json:"cases"`
}

// fixtureVerifier serves discovery and the case's key set over a fake
// transport, so the real fetch, cache and rotation paths run.
func fixtureVerifier(t *testing.T, fx tokenFixtures, jwks, afterRefetch string, fetches *int32) *Verifier {
	t.Helper()
	discovery, _ := os.ReadFile("testdata/discovery.json")
	first, _ := os.ReadFile("testdata/" + jwks)
	later := first
	if afterRefetch != "" {
		later, _ = os.ReadFile("testdata/" + afterRefetch)
	}
	var jwksCalls int32
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/openid-configuration"):
			return respond(200, discovery, nil), nil
		case strings.HasSuffix(r.URL.Path, "/jwks.json"):
			if fetches != nil {
				atomic.AddInt32(fetches, 1)
			}
			if atomic.AddInt32(&jwksCalls, 1) == 1 {
				return respond(200, first, nil), nil
			}
			return respond(200, later, nil), nil
		}
		return respond(404, nil, nil), nil
	})
	v, err := NewVerifier(VerifierConfig{
		EnvironmentID: fx.EnvironmentID,
		APIURL:        "https://api.zevauth.test",
		HTTPClient:    &http.Client{Transport: transport},
		Now:           func() time.Time { return time.Unix(fx.Now, 0) },
		ClockSkew:     time.Duration(fx.ClockSkewSeconds) * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func TestConformanceTokens(t *testing.T) {
	var fx tokenFixtures
	load(t, "tokens.json", &fx)
	if len(fx.Cases) == 0 {
		t.Fatal("no token fixtures")
	}
	for _, tc := range fx.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			v := fixtureVerifier(t, fx, tc.JWKS, tc.JWKSAfterRefetch, nil)
			claims, err := v.Verify(context.Background(), tc.Token)
			if tc.Expect.OK {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
			} else {
				var verr *VerifyError
				if !errors.As(err, &verr) || verr.Code != tc.Expect.Error {
					t.Fatalf("want %s, got %v", tc.Expect.Error, err)
				}
				if !errors.Is(err, &VerifyError{Code: tc.Expect.Error}) {
					t.Fatalf("errors.Is does not match %s", tc.Expect.Error)
				}
			}

			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
			req.Header.Set("Authorization", "Bearer "+tc.Token)
			auth := v.GetAuth(req)
			if claims != nil && auth.Claims == nil {
				t.Fatal("GetAuth lost a verified session")
			}

			if want := tc.Auth; want != nil {
				if auth.IsSignedIn != want.IsSignedIn {
					t.Fatalf("isSignedIn %v, want %v", auth.IsSignedIn, want.IsSignedIn)
				}
				if want.IsSignedIn {
					if auth.UserID != str(want.UserID) || auth.SessionID != str(want.SessionID) ||
						auth.OrganizationID != str(want.OrganizationID) || auth.OrganizationRole != str(want.OrganizationRole) {
						t.Fatalf("auth %+v, want %+v", auth, want)
					}
					if strings.Join(auth.PendingTasks, ",") != strings.Join(want.PendingTasks, ",") {
						t.Fatalf("pendingTasks %v, want %v", auth.PendingTasks, want.PendingTasks)
					}
					if auth.IsMFAVerified != want.IsMFAVerified {
						t.Fatalf("isMfaVerified %v, want %v", auth.IsMFAVerified, want.IsMFAVerified)
					}
				}
			}
			for _, h := range tc.Has {
				if got := auth.Has(h.Check); got != h.Result {
					t.Fatalf("has(%+v) = %v, want %v", h.Check, got, h.Result)
				}
			}
			for _, rc := range tc.RequireAuth {
				refusal := Check(auth, RequireOptions{AllowPendingTasks: rc.Options.AllowPendingTasks, RequireMFA: rc.Options.RequireMFA})
				if rc.Result.OK {
					if refusal != nil {
						t.Fatalf("requireAuth(%+v) refused: %v", rc.Options, refusal)
					}
					continue
				}
				if refusal == nil || refusal.Status != rc.Result.Status || refusal.Code != rc.Result.Code {
					t.Fatalf("requireAuth(%+v) = %+v, want %d %s", rc.Options, refusal, rc.Result.Status, rc.Result.Code)
				}
				rec := httptest.NewRecorder()
				refusal.ServeHTTP(rec, req)
				var body struct {
					Error struct {
						Code string `json:"code"`
					} `json:"error"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &body)
				if rec.Code != rc.Result.Status || body.Error.Code != rc.Result.Code {
					t.Fatalf("refusal response %d %s", rec.Code, rec.Body.String())
				}
			}
		})
	}
}

func TestUnknownKidRefetchCooldown(t *testing.T) {
	var fx tokenFixtures
	load(t, "tokens.json", &fx)
	var unknown, valid string
	for _, tc := range fx.Cases {
		switch tc.Name {
		case "unknown_kid":
			unknown = tc.Token
		case "valid":
			valid = tc.Token
		}
	}
	var fetches int32
	v := fixtureVerifier(t, fx, "jwks.json", "", &fetches)
	ctx := context.Background()
	if _, err := v.Verify(ctx, valid); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _ = v.Verify(ctx, unknown)
	}
	// One initial fetch, then one refetch for the unknown kid; the other
	// four fall inside the cooldown.
	if fetches != 2 {
		t.Fatalf("key set fetched %d times, want 2", fetches)
	}
}

func TestLocalKeySet(t *testing.T) {
	var fx tokenFixtures
	load(t, "tokens.json", &fx)
	jwks, _ := os.ReadFile("testdata/jwks.json")
	v, err := NewVerifier(VerifierConfig{
		EnvironmentID: fx.EnvironmentID,
		Issuer:        fx.Issuer,
		JWKS:          jwks,
		HTTPClient:    &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("fetched with a local key set"); return nil, nil })},
		Now:           func() time.Time { return time.Unix(fx.Now, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), fx.Cases[0].Token); err != nil {
		t.Fatal(err)
	}
}

func TestJWKSUnavailable(t *testing.T) {
	var fx tokenFixtures
	load(t, "tokens.json", &fx)
	v, _ := NewVerifier(VerifierConfig{
		EnvironmentID: fx.EnvironmentID,
		APIURL:        "https://api.zevauth.test",
		HTTPClient:    &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })},
		Now:           func() time.Time { return time.Unix(fx.Now, 0) },
	})
	if _, err := v.Verify(context.Background(), fx.Cases[0].Token); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestConformanceBearer(t *testing.T) {
	var fx struct {
		Cases []struct {
			Header *string `json:"header"`
			Token  *string `json:"token"`
		} `json:"cases"`
	}
	load(t, "bearer.json", &fx)
	for i, tc := range fx.Cases {
		if got := BearerFrom(str(tc.Header)); got != str(tc.Token) {
			t.Fatalf("case %d: BearerFrom(%q) = %q, want %q", i, str(tc.Header), got, str(tc.Token))
		}
	}
}

func TestConformanceWebhooks(t *testing.T) {
	var fx struct {
		Now              int64  `json:"now"`
		Secret           string `json:"secret"`
		ToleranceSeconds int    `json:"toleranceSeconds"`
		Cases            []struct {
			Name      string `json:"name"`
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
			Valid     bool   `json:"valid"`
			Error     string `json:"error"`
		} `json:"cases"`
	}
	load(t, "webhooks.json", &fx)
	opts := WebhookOptions{Tolerance: time.Duration(fx.ToleranceSeconds) * time.Second, Now: func() time.Time { return time.Unix(fx.Now, 0) }}
	for _, tc := range fx.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			secret := fx.Secret
			err := VerifyWebhook([]byte(tc.Payload), tc.Signature, secret, opts)
			if tc.Valid {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				event, err := ConstructWebhookEvent([]byte(tc.Payload), tc.Signature, secret, opts)
				if err != nil || event.ID == "" || event.Type == "" {
					t.Fatalf("construct: %+v %v", event, err)
				}
				return
			}
			var werr *WebhookError
			if !errors.As(err, &werr) || werr.Code != tc.Error {
				t.Fatalf("want %s, got %v", tc.Error, err)
			}
		})
	}
}

func TestConformanceAPIErrors(t *testing.T) {
	var fx struct {
		Cases []struct {
			Name     string            `json:"name"`
			Status   int               `json:"status"`
			Headers  map[string]string `json:"headers"`
			Body     json.RawMessage   `json:"body"`
			BodyText *string           `json:"bodyText"`
			Expect   struct {
				Code              string `json:"code"`
				Status            int    `json:"status"`
				Retry             bool   `json:"retry"`
				RetryAfterSeconds int    `json:"retryAfterSeconds"`
				RequestID         string `json:"requestId"`
			} `json:"expect"`
		} `json:"cases"`
	}
	load(t, "api-errors.json", &fx)
	for _, tc := range fx.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			body := []byte(tc.Body)
			if tc.BodyText != nil {
				body = []byte(*tc.BodyText)
			}
			header := http.Header{}
			for k, v := range tc.Headers {
				header.Set(k, v)
			}
			var calls int32
			var waits []time.Duration
			client, err := NewClient("sk_test_fixture", ClientOptions{
				APIURL: "https://api.zevauth.test",
				HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					atomic.AddInt32(&calls, 1)
					if r.Header.Get("User-Agent") != "zevauth-go/"+Version {
						t.Errorf("user agent %q", r.Header.Get("User-Agent"))
					}
					if r.Header.Get("Idempotency-Key") != "" {
						t.Error("sent an Idempotency-Key")
					}
					return respond(tc.Status, body, header.Clone()), nil
				})},
				Sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Users.Get(context.Background(), "user_1")
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("want APIError, got %v", err)
			}
			if apiErr.Code != tc.Expect.Code || apiErr.Status != tc.Expect.Status || apiErr.RequestID != tc.Expect.RequestID {
				t.Fatalf("got %+v, want %+v", apiErr, tc.Expect)
			}
			wantCalls := int32(1)
			if tc.Expect.Retry {
				wantCalls = 3 // the first attempt plus the default two retries
			}
			if calls != wantCalls {
				t.Fatalf("%d attempts, want %d", calls, wantCalls)
			}
			if tc.Expect.RetryAfterSeconds > 0 && (len(waits) == 0 || waits[0] != time.Duration(tc.Expect.RetryAfterSeconds)*time.Second) {
				t.Fatalf("waits %v, want Retry-After %ds", waits, tc.Expect.RetryAfterSeconds)
			}
		})
	}
}

func TestConformanceBridge(t *testing.T) {
	var fx struct {
		Now           int64  `json:"now"`
		EnvironmentID string `json:"environmentId"`
		AppOrigin     string `json:"appOrigin"`
		Cases         []struct {
			Name    string `json:"name"`
			Request struct {
				Method       string          `json:"method"`
				Origin       string          `json:"origin"`
				BridgeHeader bool            `json:"bridgeHeader"`
				Body         json.RawMessage `json:"body"`
			} `json:"request"`
			Expect struct {
				Status        int    `json:"status"`
				Code          string `json:"code"`
				Cookie        string `json:"cookie"`
				MaxAgeSeconds int    `json:"maxAgeSeconds"`
			} `json:"expect"`
		} `json:"cases"`
	}
	load(t, "bridge.json", &fx)
	var tokens tokenFixtures
	load(t, "tokens.json", &tokens)
	for _, tc := range fx.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			bridge := &Bridge{Verifier: fixtureVerifier(t, tokens, "jwks.json", "", nil)}
			var body io.Reader
			if len(tc.Request.Body) > 0 {
				body = bytes.NewReader(tc.Request.Body)
			}
			req := httptest.NewRequest(tc.Request.Method, fx.AppOrigin+"/zevauth/bridge", body)
			req.Header.Set("Origin", tc.Request.Origin)
			if tc.Request.BridgeHeader {
				req.Header.Set(BridgeHeader, "1")
			}
			rec := httptest.NewRecorder()
			bridge.ServeHTTP(rec, req)

			if rec.Code != tc.Expect.Status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.Expect.Status, rec.Body.String())
			}
			if tc.Expect.Code != "" && !strings.Contains(rec.Body.String(), `"code":"`+tc.Expect.Code+`"`) {
				t.Fatalf("body %s, want code %s", rec.Body.String(), tc.Expect.Code)
			}
			cookies := rec.Result().Cookies()
			switch tc.Expect.Cookie {
			case "unchanged":
				if len(cookies) != 0 {
					t.Fatalf("cookies changed: %v", cookies)
				}
			case "cleared":
				if len(cookies) != 2 || cookies[0].MaxAge >= 0 || cookies[1].MaxAge >= 0 {
					t.Fatalf("cookies not cleared: %v", cookies)
				}
			case "set":
				if len(cookies) != 2 || cookies[0].Name != "__Host-zevauth_session" || cookies[0].MaxAge != tc.Expect.MaxAgeSeconds {
					t.Fatalf("session cookie %v, want max-age %d", cookies, tc.Expect.MaxAgeSeconds)
				}
				if !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode {
					t.Fatalf("cookie attributes %+v", cookies[0])
				}
				if cookies[1].Name != "__Host-zevauth_client" || cookies[1].Value != "1" {
					t.Fatalf("client cookie %v", cookies[1])
				}
			}
		})
	}
}
