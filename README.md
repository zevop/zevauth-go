# ZevAuth for Go

Verify ZevAuth sessions, call the ZevAuth backend API and check webhook
signatures from any Go server. Standard library only.

```sh
go get github.com/zevop/zevauth-go
```

Requires Go 1.22 or later.

## Verify a request

```go
verifier, err := zevauth.NewVerifier(zevauth.VerifierConfig{
	EnvironmentID: "env_live_…",
})

// Middleware puts the Auth in the request context.
handler := zevauth.Middleware(verifier, zevauth.MiddlewareOptions{Require: true})(mux)

// In a handler:
auth := zevauth.AuthFromContext(r.Context())
auth.UserID          // "user_…"
auth.OrganizationID  // "" when not acting in an organization
auth.Has(zevauth.HasCheck{Permission: "org:members:manage"})
```

Or decide per route:

```go
auth, refusal := verifier.RequireAuth(r, zevauth.RequireOptions{RequireMFA: true})
if refusal != nil {
	refusal.ServeHTTP(w, r) // 401 unauthorized, or 403 session_task_pending / mfa_required
	return
}
```

`GetAuth` never fails for a missing, expired or forged token: those mean
nobody is signed in. Only RS256 is accepted, the issuer comes from your
environment's discovery document, the audience is enforced, and keys are
cached for up to 10 minutes with a rate-limited refetch on rotation.

## Server-rendered pages

The browser holds the session. With the session bridge, the browser SDK
posts its access token to your server, which keeps it in your own
HttpOnly cookie:

```go
bridge := &zevauth.Bridge{Verifier: verifier}

mux.Handle("/zevauth/bridge", bridge)
mux.Handle(zevauth.DefaultHandshakePath, zevauth.HandshakeHandler(zevauth.HandshakeOptions{
	PublishableKey: "pk_live_…",
	BridgePath:     "/zevauth/bridge",
}))

http.ListenAndServe(":8080", bridge.Middleware(zevauth.MiddlewareOptions{})(mux))
```

In the browser: `sessionBridge: { url: '/zevauth/bridge' }`. Your server
never refreshes a session; when the cookie expires, the handshake lets the
browser refresh it and come straight back.

## Backend API

```go
client, err := zevauth.NewClient(os.Getenv("ZEVAUTH_SECRET_KEY"), zevauth.ClientOptions{})

user, err := client.Users.Get(ctx, "user_…")

it := client.Users.Iter(ctx, zevauth.ListUsersParams{})
for it.Next() {
	fmt.Println(it.User().ID)
}
if err := it.Err(); err != nil { … }

var apiErr *zevauth.APIError
if errors.As(err, &apiErr) {
	apiErr.Code      // "not_found", "rate_limited", …
	apiErr.RequestID // quote this to ZevAuth support
}
```

Retries 429, 502, 503, 504 and network failures (never a 500, which may
have run), honouring `Retry-After`.

## Webhooks

```go
body, _ := io.ReadAll(r.Body) // the raw bytes; never re-encode before verifying
event, err := zevauth.ConstructWebhookEvent(body, r.Header.Get("zevauth-signature"), secret, zevauth.WebhookOptions{})
```

## Conformance

Every ZevAuth server library implements the same contract,
[`spec/SERVER_SDK.md`](https://github.com/zevop/zevauth-sdk/tree/main/spec),
and passes the same fixtures. They are vendored in `testdata/`; refresh
them with `./scripts/sync-fixtures.sh ../zevauth-sdk`, then `go test ./...`.

## Documentation

<https://docs.zevauth.com/sdk/go>

## Support

Questions and bug reports: open an issue here, or contact ZevAuth support.

## License

[MIT](LICENSE). Copyright (c) 2026 Zevop Inc.
