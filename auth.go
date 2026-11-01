package zevauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Auth is who a request is from (contract §2.1). The zero value is
// signed out.
type Auth struct {
	IsSignedIn       bool
	UserID           string
	SessionID        string
	OrganizationID   string
	OrganizationRole string
	Claims           *Claims // nil when signed out
	PendingTasks     []string
	IsMFAVerified    bool
}

// HasCheck is the argument to Auth.Has.
type HasCheck struct {
	Role       string
	Permission string
}

// Has reports whether the active organization grants every given role
// and permission. False with no active organization, and false when
// neither is given.
func (a Auth) Has(check HasCheck) bool {
	if a.Claims == nil || a.Claims.OrgID == "" {
		return false
	}
	if check.Role == "" && check.Permission == "" {
		return false
	}
	if check.Role != "" && a.Claims.OrgRole != check.Role {
		return false
	}
	if check.Permission != "" && !contains(a.Claims.OrgPermissions, check.Permission) {
		return false
	}
	return true
}

// AuthFromClaims builds the Auth for verified claims.
func AuthFromClaims(c *Claims) Auth {
	tasks := c.PendingTasks
	if tasks == nil {
		tasks = []string{}
	}
	return Auth{
		IsSignedIn:       true,
		UserID:           c.Subject,
		SessionID:        c.SessionID,
		OrganizationID:   c.OrgID,
		OrganizationRole: c.OrgRole,
		Claims:           c,
		PendingTasks:     tasks,
		IsMFAVerified:    contains(c.AMR, "mfa"),
	}
}

func signedOut() Auth { return Auth{PendingTasks: []string{}} }

// BearerFrom extracts a session token from an Authorization header value
// (contract §1.5). It returns "" for no header, another scheme, an empty
// token, or an API key sent in the wrong place.
func BearerFrom(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	token := strings.TrimSpace(header[len("Bearer "):])
	if token == "" || strings.HasPrefix(token, "pk_") || strings.HasPrefix(token, "sk_") {
		return ""
	}
	return token
}

// GetAuth reads the Authorization header and verifies it. It never
// returns an error for a missing or bad token: those mean signed out.
// For server-rendered pages, use Bridge.GetAuth, which also reads the
// session cookie.
func (v *Verifier) GetAuth(r *http.Request) Auth {
	token := BearerFrom(r.Header.Get("Authorization"))
	if token == "" {
		return signedOut()
	}
	claims, err := v.Verify(r.Context(), token)
	if err != nil {
		return signedOut()
	}
	return AuthFromClaims(claims)
}

// RequireOptions are the options for RequireAuth (contract §2.3).
type RequireOptions struct {
	// AllowPendingTasks serves a session that still has tasks to finish.
	// Only for routes that help finish them.
	AllowPendingTasks bool
	// RequireMFA refuses a session that did not pass a second factor.
	RequireMFA bool
}

// Refusal codes produced by RequireAuth.
const (
	CodeUnauthorized       = "unauthorized"
	CodeSessionTaskPending = "session_task_pending"
	CodeMFARequired        = "mfa_required"
)

// Refusal is why RequireAuth refused a request. It is an error, and an
// http.Handler that writes the shared error envelope.
type Refusal struct {
	Status       int
	Code         string
	Message      string
	PendingTasks []string // set for session_task_pending
}

func (r *Refusal) Error() string { return "zevauth: " + r.Code + ": " + r.Message }

// ServeHTTP writes { "error": { "code", "message" } } with the status.
func (r *Refusal) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	body := map[string]any{"code": r.Code, "message": r.Message}
	if r.Code == CodeSessionTaskPending {
		body["pendingTasks"] = r.PendingTasks
	}
	writeJSON(w, r.Status, map[string]any{"error": body})
}

// Check applies the RequireAuth rules to an Auth, in the contract's
// order. It returns nil when the request may proceed.
func Check(a Auth, opts RequireOptions) *Refusal {
	if !a.IsSignedIn {
		return &Refusal{Status: http.StatusUnauthorized, Code: CodeUnauthorized, Message: "Sign in to continue."}
	}
	if len(a.PendingTasks) > 0 && !opts.AllowPendingTasks {
		return &Refusal{
			Status:       http.StatusForbidden,
			Code:         CodeSessionTaskPending,
			Message:      "Finish setting up your account to continue.",
			PendingTasks: a.PendingTasks,
		}
	}
	if opts.RequireMFA && !a.IsMFAVerified {
		return &Refusal{Status: http.StatusForbidden, Code: CodeMFARequired, Message: "Two-step verification is required."}
	}
	return nil
}

// RequireAuth is GetAuth that refuses. On refusal it returns a *Refusal,
// which can be served directly as the response.
func (v *Verifier) RequireAuth(r *http.Request, opts RequireOptions) (Auth, *Refusal) {
	a := v.GetAuth(r)
	return a, Check(a, opts)
}

type authContextKey struct{}

// WithAuth returns a context carrying a.
func WithAuth(ctx context.Context, a Auth) context.Context {
	return context.WithValue(ctx, authContextKey{}, a)
}

// AuthFromContext returns the Auth that Middleware stored, or a
// signed-out Auth when there is none.
func AuthFromContext(ctx context.Context) Auth {
	if a, ok := ctx.Value(authContextKey{}).(Auth); ok {
		return a
	}
	return signedOut()
}

// Authenticator is anything that can read a request's Auth: a
// *Verifier (header only) or a *Bridge (header, then cookie).
type Authenticator interface {
	GetAuth(r *http.Request) Auth
}

// MiddlewareOptions configure Middleware.
type MiddlewareOptions struct {
	// Require refuses requests that fail RequireAuth's rules. Without it
	// every request passes through and handlers decide, using
	// AuthFromContext.
	Require bool
	RequireOptions
}

// Middleware stores the request's Auth in its context. With Require set
// it answers refusals itself with the shared error envelope.
func Middleware(auth Authenticator, opts MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a := auth.GetAuth(r)
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

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
