package zevauth_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	zevauth "github.com/zevop/zevauth-go"
)

// Protect an API: the middleware verifies the bearer token the browser
// SDK sends, and refuses requests that are not signed in.
func ExampleMiddleware() {
	verifier, err := zevauth.NewVerifier(zevauth.VerifierConfig{EnvironmentID: "env_live_123"})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		auth := zevauth.AuthFromContext(r.Context())
		fmt.Fprintf(w, "hello %s", auth.UserID)
	})

	protected := zevauth.Middleware(verifier, zevauth.MiddlewareOptions{Require: true})(mux)
	_ = http.ListenAndServe(":8080", protected)
}

// Decide per handler: require two-step verification for one route.
func ExampleVerifier_RequireAuth() {
	verifier, _ := zevauth.NewVerifier(zevauth.VerifierConfig{EnvironmentID: "env_live_123"})

	http.HandleFunc("/api/payouts", func(w http.ResponseWriter, r *http.Request) {
		auth, refusal := verifier.RequireAuth(r, zevauth.RequireOptions{RequireMFA: true})
		if refusal != nil {
			refusal.ServeHTTP(w, r) // 401 or 403 with { "error": { "code", "message" } }
			return
		}
		if !auth.Has(zevauth.HasCheck{Permission: "org:billing:manage"}) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprintln(w, "ok")
	})
}

// Server-rendered pages: the browser SDK posts its token to the bridge,
// and every page request reads it from your own HttpOnly cookie.
func ExampleBridge() {
	verifier, _ := zevauth.NewVerifier(zevauth.VerifierConfig{EnvironmentID: "env_live_123"})
	bridge := &zevauth.Bridge{Verifier: verifier}

	mux := http.NewServeMux()
	mux.Handle("/zevauth/bridge", bridge)
	mux.Handle(zevauth.DefaultHandshakePath, zevauth.HandshakeHandler(zevauth.HandshakeOptions{
		PublishableKey: "pk_live_123",
		BridgePath:     "/zevauth/bridge",
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if auth := zevauth.AuthFromContext(r.Context()); auth.IsSignedIn {
			fmt.Fprintf(w, "<p>Signed in as %s</p>", auth.UserID)
			return
		}
		fmt.Fprint(w, `<a href="/sign-in">Sign in</a>`)
	})

	_ = http.ListenAndServe(":8080", bridge.Middleware(zevauth.MiddlewareOptions{})(mux))
}

// Call the backend API with your secret key.
func ExampleNewClient() {
	client, err := zevauth.NewClient(os.Getenv("ZEVAUTH_SECRET_KEY"), zevauth.ClientOptions{})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	it := client.Users.Iter(ctx, zevauth.ListUsersParams{Metadata: map[string]string{"plan": "pro"}})
	for it.Next() {
		fmt.Println(it.User().ID)
	}
	if err := it.Err(); err != nil {
		log.Fatal(err)
	}

	if _, err := client.Users.SetBlocked(ctx, "user_123", true); err != nil {
		log.Println(err)
	}
}

// Webhooks: verify the raw body before parsing it.
func ExampleConstructWebhookEvent() {
	http.HandleFunc("/webhooks/zevauth", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		event, err := zevauth.ConstructWebhookEvent(body, r.Header.Get(zevauth.WebhookSignatureHeader), os.Getenv("ZEVAUTH_WEBHOOK_SECRET"), zevauth.WebhookOptions{})
		if err != nil {
			http.Error(w, "bad signature", http.StatusBadRequest)
			return
		}
		switch event.Type {
		case "user.created":
			// event.Data holds the user
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
