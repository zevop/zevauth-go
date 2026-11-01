package zevauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Session bridge constants (contract §5).
const (
	BridgeHeader         = "x-zevauth-bridge"
	HandshakeMarker      = "__zevauth_handshake"
	DefaultHandshakePath = "/zevauth/handshake"
	defaultUIScriptURL   = "https://cdn.jsdelivr.net/npm/@zevauth/ui@0/dist/zevauth-ui.global.js"
	clientCookieMaxAge   = 30 * 24 * 60 * 60
)

// Bridge lets server-rendered pages know who is signed in. The browser
// SDK posts its access token to the bridge endpoint whenever it changes;
// the bridge keeps it in your own HttpOnly cookie. The server never
// refreshes: refresh tokens rotate on every use, so only the browser may.
type Bridge struct {
	Verifier *Verifier

	// AllowedOrigins may post to the endpoint. Defaults to the request's
	// own origin. List every page origin when using CookieDomain.
	AllowedOrigins []string

	// CookieDomain shares the cookies with subdomains (__Secure- names).
	CookieDomain string

	// Insecure drops the Secure attribute and cookie prefixes, for plain
	// http local development only.
	Insecure bool

	// HandshakePath is where HandshakeHandler is mounted. Defaults to
	// /zevauth/handshake.
	HandshakePath string
}

// CookieNames returns the session and client cookie names for this
// configuration.
func (b *Bridge) CookieNames() (session, client string) {
	prefix := "__Host-"
	switch {
	case b.Insecure:
		prefix = ""
	case b.CookieDomain != "":
		prefix = "__Secure-"
	}
	return prefix + "zevauth_session", prefix + "zevauth_client"
}

// ServeHTTP is the bridge endpoint. Mount it at the URL you give the
// browser SDK's sessionBridge option.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method_not_allowed", "The session bridge accepts POST only."))
		return
	}
	if r.Header.Get(BridgeHeader) != "1" {
		writeJSON(w, http.StatusForbidden, errorBody("bridge_header_missing", "Send the "+BridgeHeader+": 1 header. The ZevAuth browser SDK does this for you."))
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && !contains(b.allowedOrigins(r), origin) {
		writeJSON(w, http.StatusForbidden, errorBody("bridge_origin_not_allowed", origin+" may not post sessions here. Add it to AllowedOrigins."))
		return
	}

	var body struct {
		Token *string `json:"token"`
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || json.Unmarshal(data, &body) != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid_request", `Expected a JSON body: { "token": string | null }.`))
		return
	}

	session, client := b.CookieNames()
	if body.Token == nil || *body.Token == "" {
		b.clear(w, session, client)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	claims, err := b.Verifier.Verify(r.Context(), *body.Token)
	if err != nil {
		reason := CodeMalformedToken
		var verr *VerifyError
		if errors.As(err, &verr) {
			reason = verr.Code
		}
		// A refused token also ends whatever was there, so a stale
		// cookie never outlives a refusal.
		b.clear(w, session, client)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{
			"code": CodeUnauthorized, "message": "That session token was refused.", "reason": reason,
		}})
		return
	}

	now := b.Verifier.cfg.Now().Unix()
	maxAge := claims.ExpiresAt - now
	if maxAge < 0 || claims.ExpiresAt == 0 {
		maxAge = 0
	}
	// The access token, until it expires. Never the refresh token.
	http.SetCookie(w, b.cookie(session, *body.Token, int(maxAge)))
	http.SetCookie(w, b.cookie(client, "1", clientCookieMaxAge))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// BridgedAuth is an Auth plus whether the browser should be asked to
// refresh the session cookie.
type BridgedAuth struct {
	Auth
	NeedsHandshake bool
}

// GetAuth reads the Authorization header, then the session cookie. Like
// Verifier.GetAuth it never fails: a bad token is signed out.
func (b *Bridge) GetAuth(r *http.Request) Auth { return b.Read(r).Auth }

// Read is GetAuth plus NeedsHandshake.
func (b *Bridge) Read(r *http.Request) BridgedAuth {
	header := BearerFrom(r.Header.Get("Authorization"))
	session, client := b.CookieNames()
	token := header
	if token == "" {
		if c, err := r.Cookie(session); err == nil {
			token = c.Value
		}
	}
	hasClient := false
	if c, err := r.Cookie(client); err == nil && c.Value == "1" {
		hasClient = true
	}

	if token == "" {
		return BridgedAuth{Auth: signedOut(), NeedsHandshake: header == "" && hasClient}
	}
	claims, err := b.Verifier.Verify(r.Context(), token)
	if err != nil {
		expired := errors.Is(err, ErrTokenExpired)
		return BridgedAuth{Auth: signedOut(), NeedsHandshake: header == "" && (expired || hasClient)}
	}
	return BridgedAuth{Auth: AuthFromClaims(claims)}
}

// Authenticate reads the request and, when the session cookie needs
// refreshing, answers it itself: a page navigation is redirected to the
// handshake, anything else gets 401 session_refresh_required. It reports
// whether it wrote a response; if so, stop handling the request.
func (b *Bridge) Authenticate(w http.ResponseWriter, r *http.Request) (Auth, bool) {
	a := b.Read(r)
	if !a.NeedsHandshake {
		return a.Auth, false
	}
	// Back from a handshake and still no session: render signed out.
	// This is the loop guard.
	if r.URL.Query().Has(HandshakeMarker) {
		return a.Auth, false
	}
	navigation := (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
	if !navigation {
		writeJSON(w, http.StatusUnauthorized, errorBody("session_refresh_required", "The session cookie expired. Send the SDK token in Authorization, or reload the page."))
		return a.Auth, true
	}
	path := b.HandshakePath
	if path == "" {
		path = DefaultHandshakePath
	}
	target := url.URL{Path: path, RawQuery: url.Values{"redirect_url": {r.URL.RequestURI()}}.Encode()}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target.String(), http.StatusFound)
	return a.Auth, true
}

// Middleware is Authenticate as middleware: it handles the handshake,
// stores the Auth in the context, and with Require set refuses like
// RequireAuth.
func (b *Bridge) Middleware(opts MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a, handled := b.Authenticate(w, r)
			if handled {
				return
			}
			if opts.Require {
				if refusal := Check(a, opts.RequireOptions); refusal != nil {
					refusal.ServeHTTP(w, r)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(WithAuth(r.Context(), a)))
		})
	}
}

// HandshakeOptions configure HandshakeHandler.
type HandshakeOptions struct {
	PublishableKey string
	// BridgePath is where the bridge endpoint is mounted.
	BridgePath string
	APIURL     string
	// UIScriptURL serves your own copy of @zevauth/ui, e.g. under a
	// strict Content Security Policy.
	UIScriptURL string
}

// HandshakeHandler serves the handshake page: plain HTML that lets the
// browser SDK refresh the session, posts it to the bridge, and returns to
// the page that asked. Mount it at the bridge's HandshakePath.
func HandshakeHandler(opts HandshakeOptions) http.Handler {
	script := opts.UIScriptURL
	if script == "" {
		script = defaultUIScriptURL
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested := r.URL.Query().Get("redirect_url")
		// Same-site paths only. //evil.example and /\evil.example are
		// absolute URLs to a browser: this guard stops an open redirect.
		if !safeRedirect(requested) {
			requested = "/"
		}
		back, err := url.Parse(requested)
		if err != nil {
			back = &url.URL{Path: "/"}
		}
		q := back.Query()
		q.Set(HandshakeMarker, "1")
		back.RawQuery = q.Encode()

		config, _ := json.Marshal(map[string]any{
			"publishableKey": opts.PublishableKey,
			"apiUrl":         nullable(opts.APIURL),
			"bridge":         opts.BridgePath,
			"back":           back.RequestURI(),
		})
		// json.Marshal escapes <, > and & as < etc., so the config
		// cannot close the script element.
		page := fmt.Sprintf(`<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>Signing in…</title>
<script src="%s"></script>
<script>
(async function () {
  var c = %s;
  try {
    window.ZevAuthUI.init({ publishableKey: c.publishableKey, apiUrl: c.apiUrl || undefined, sessionBridge: { url: c.bridge } });
    var client = window.ZevAuthUI.getClient();
    await client.load();
    await client.syncSessionBridge();
  } catch (e) {}
  location.replace(c.back);
})();
</script>`, html.EscapeString(script), config)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "same-origin")
		_, _ = io.WriteString(w, page)
	})
}

func safeRedirect(path string) bool {
	return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !strings.HasPrefix(path, `/\`)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (b *Bridge) allowedOrigins(r *http.Request) []string {
	if len(b.AllowedOrigins) > 0 {
		return b.AllowedOrigins
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return []string{scheme + "://" + r.Host}
}

func (b *Bridge) cookie(name, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !b.Insecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   b.CookieDomain,
	}
	if maxAge == 0 {
		// net/http omits Max-Age=0; a past Expires clears the cookie.
		c.MaxAge = -1
		c.Expires = time.Unix(0, 0)
	}
	return c
}

func (b *Bridge) clear(w http.ResponseWriter, names ...string) {
	for _, name := range names {
		http.SetCookie(w, b.cookie(name, "", 0))
	}
}

func errorBody(code, message string) map[string]any {
	return map[string]any{"error": map[string]any{"code": code, "message": message}}
}
