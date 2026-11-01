package zevauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tokenNamed(t *testing.T, fx tokenFixtures, name string) string {
	t.Helper()
	for _, tc := range fx.Cases {
		if tc.Name == name {
			return tc.Token
		}
	}
	t.Fatalf("no token fixture %q", name)
	return ""
}

func bridgeFixture(t *testing.T) (*Bridge, tokenFixtures) {
	var fx tokenFixtures
	load(t, "tokens.json", &fx)
	return &Bridge{Verifier: fixtureVerifier(t, fx, "jwks.json", "", nil)}, fx
}

func page(method, target string, cookies map[string]string) *http.Request {
	req := httptest.NewRequest(method, "https://app.example.com"+target, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	return req
}

func TestBridgeReadsTheCookie(t *testing.T) {
	b, fx := bridgeFixture(t)
	a, handled := b.Authenticate(httptest.NewRecorder(), page("GET", "/dashboard", map[string]string{
		"__Host-zevauth_session": tokenNamed(t, fx, "valid"),
		"__Host-zevauth_client":  "1",
	}))
	if handled || !a.IsSignedIn || a.UserID != "user_fixture_1" {
		t.Fatalf("handled=%v auth=%+v", handled, a)
	}
}

func TestBridgeHandshakeOnExpiredCookie(t *testing.T) {
	b, fx := bridgeFixture(t)
	rec := httptest.NewRecorder()
	_, handled := b.Authenticate(rec, page("GET", "/dashboard?tab=2", map[string]string{
		"__Host-zevauth_session": tokenNamed(t, fx, "expired"),
		"__Host-zevauth_client":  "1",
	}))
	if !handled || rec.Code != http.StatusFound {
		t.Fatalf("handled=%v status=%d", handled, rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/zevauth/handshake?redirect_url=%2Fdashboard%3Ftab%3D2" {
		t.Fatalf("location %q", loc)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("handshake redirect is cacheable")
	}
}

func TestBridgeHandshakeWhenOnlyClientCookieRemains(t *testing.T) {
	b, _ := bridgeFixture(t)
	rec := httptest.NewRecorder()
	_, handled := b.Authenticate(rec, page("GET", "/", map[string]string{"__Host-zevauth_client": "1"}))
	if !handled || rec.Code != http.StatusFound {
		t.Fatalf("handled=%v status=%d", handled, rec.Code)
	}
}

func TestBridgeNoHandshakeForSomeoneWhoNeverSignedIn(t *testing.T) {
	b, _ := bridgeFixture(t)
	a, handled := b.Authenticate(httptest.NewRecorder(), page("GET", "/", nil))
	if handled || a.IsSignedIn {
		t.Fatalf("handled=%v auth=%+v", handled, a)
	}
}

func TestBridgeLoopGuard(t *testing.T) {
	b, _ := bridgeFixture(t)
	a, handled := b.Authenticate(httptest.NewRecorder(), page("GET", "/?"+HandshakeMarker+"=1", map[string]string{"__Host-zevauth_client": "1"}))
	if handled || a.IsSignedIn {
		t.Fatal("handshook again on the way back from a handshake")
	}
}

func TestBridgeNonNavigationGets401(t *testing.T) {
	b, _ := bridgeFixture(t)
	req := httptest.NewRequest("POST", "https://app.example.com/api/things", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-zevauth_client", Value: "1"})
	rec := httptest.NewRecorder()
	_, handled := b.Authenticate(rec, req)
	if !handled || rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "session_refresh_required") {
		t.Fatalf("handled=%v %d %s", handled, rec.Code, rec.Body.String())
	}
}

func TestBridgeHeaderBeatsCookieAndNeverHandshakes(t *testing.T) {
	b, fx := bridgeFixture(t)
	req := page("GET", "/", map[string]string{"__Host-zevauth_client": "1"})
	req.Header.Set("Authorization", "Bearer "+tokenNamed(t, fx, "expired"))
	_, handled := b.Authenticate(httptest.NewRecorder(), req)
	if handled {
		t.Fatal("a request that sent its own token was sent to the handshake")
	}
}

func TestCookieNames(t *testing.T) {
	cases := []struct {
		b               Bridge
		session, client string
	}{
		{Bridge{}, "__Host-zevauth_session", "__Host-zevauth_client"},
		{Bridge{CookieDomain: "example.com"}, "__Secure-zevauth_session", "__Secure-zevauth_client"},
		{Bridge{Insecure: true}, "zevauth_session", "zevauth_client"},
	}
	for _, c := range cases {
		s, cl := c.b.CookieNames()
		if s != c.session || cl != c.client {
			t.Fatalf("%+v: %s %s", c.b, s, cl)
		}
	}
}

func TestHandshakePageGuards(t *testing.T) {
	h := HandshakeHandler(HandshakeOptions{PublishableKey: "pk_test_x", BridgePath: "/zevauth/bridge"})
	for redirect, want := range map[string]string{
		"/dashboard?a=1":       `"/dashboard?__zevauth_handshake=1&a=1"`,
		"//evil.example/x":     `"/?__zevauth_handshake=1"`,
		`/\evil.example`:       `"/?__zevauth_handshake=1"`,
		"https://evil.example": `"/?__zevauth_handshake=1"`,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/zevauth/handshake?redirect_url="+urlQueryEscape(redirect), nil))
		body := strings.ReplaceAll(rec.Body.String(), "\\"+"u0026", "&")
		if !strings.Contains(body, `"back":`+want) {
			t.Fatalf("redirect %q: page does not return to %s\n%s", redirect, want, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/zevauth/handshake?redirect_url=/%3C/script%3E", nil))
	if strings.Contains(rec.Body.String(), "</script></script>") || strings.Count(rec.Body.String(), "</script>") != 2 {
		t.Fatal("redirect_url escaped the script element")
	}
}

func urlQueryEscape(s string) string {
	r := strings.NewReplacer("%", "%25", "&", "%26", "?", "%3F", "=", "%3D", "#", "%23", `\`, "%5C", "/", "%2F", ":", "%3A")
	return r.Replace(s)
}

func TestMiddleware(t *testing.T) {
	var fx tokenFixtures
	load(t, "tokens.json", &fx)
	v := fixtureVerifier(t, fx, "jwks.json", "", nil)
	var seen Auth
	h := Middleware(v, MiddlewareOptions{Require: true, RequireOptions: RequireOptions{RequireMFA: true}})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = AuthFromContext(r.Context()) }),
	)

	for name, want := range map[string]int{"valid_mfa": 200, "valid": 403, "expired": 401, "valid_pending_task": 403} {
		seen = Auth{}
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenNamed(t, fx, name))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: status %d, want %d (%s)", name, rec.Code, want, rec.Body.String())
		}
		if want == 200 && seen.UserID != "user_fixture_1" {
			t.Fatalf("%s: handler did not get the auth", name)
		}
	}
	if AuthFromContext(context.Background()).IsSignedIn {
		t.Fatal("empty context reads as signed in")
	}
}

func TestPendingTaskBodyListsTasks(t *testing.T) {
	rec := httptest.NewRecorder()
	Check(Auth{IsSignedIn: true, PendingTasks: []string{"setup_mfa"}}, RequireOptions{}).ServeHTTP(rec, nil)
	var body struct {
		Error struct {
			PendingTasks []string `json:"pendingTasks"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Error.PendingTasks) != 1 || body.Error.PendingTasks[0] != "setup_mfa" {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestClientKeyChecks(t *testing.T) {
	for key, code := range map[string]string{"": CodeMissingSecretKey, "pk_test_abc": CodeWrongKeyType} {
		_, err := NewClient(key, ClientOptions{})
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Code != code {
			t.Fatalf("%q: %v", key, err)
		}
	}
}

func TestUsersIterFollowsCursors(t *testing.T) {
	var calls int32
	client, _ := NewClient("sk_test_x", ClientOptions{
		APIURL: "https://api.zevauth.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			n := atomic.AddInt32(&calls, 1)
			if r.URL.Query().Get("metadata[plan]") != "pro" {
				t.Errorf("metadata filter missing: %s", r.URL.RawQuery)
			}
			after := r.URL.Query().Get("after")
			body := fmt.Sprintf(`{"data":[{"id":"user_%d"}],"hasMore":%v,"next":"cur_%d","totalCount":2}`, n, after == "", n)
			return respond(200, []byte(body), nil), nil
		})},
	})
	it := client.Users.Iter(context.Background(), ListUsersParams{Metadata: map[string]string{"plan": "pro"}})
	var ids []string
	for it.Next() {
		ids = append(ids, it.User().ID)
	}
	if it.Err() != nil || strings.Join(ids, ",") != "user_1,user_2" {
		t.Fatalf("ids %v err %v", ids, it.Err())
	}
}

func TestNetworkErrorRetriesThenReports(t *testing.T) {
	var calls int32
	client, _ := NewClient("sk_test_x", ClientOptions{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			atomic.AddInt32(&calls, 1)
			return nil, errors.New("dial tcp: connection refused")
		})},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	err := client.Organizations.Delete(context.Background(), "org_1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != CodeNetworkError || apiErr.Status != 0 || calls != 3 {
		t.Fatalf("err %v calls %d", err, calls)
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 3200 * time.Millisecond, 4 * time.Second, 4 * time.Second}
	for i, w := range want {
		if got := backoff(i); got != w {
			t.Fatalf("backoff(%d) = %v, want %v", i, got, w)
		}
	}
}
