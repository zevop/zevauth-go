# ZevAuth for Go

Verify ZevAuth sessions, call the ZevAuth backend API and check webhook
signatures from net/http and any Go server.

> In development. The first release is on its way; until then, the API in
> this repository can change.

```
go get github.com/zevop/zevauth-go
```

## What it does

- **Verifies session tokens** against your environment's published keys,
  with key caching and rotation handled for you.
- **Reads who is signed in** on every request, including their active
  organization, role and permissions, from a bearer token or a session
  cookie for server-rendered apps.
- **Calls the backend API** with your secret key: users, organizations,
  sessions and two-step verification.
- **Checks webhook signatures**, so you only act on events ZevAuth sent.

Every ZevAuth server library implements the same contract and passes the
same conformance tests, so the behaviour here matches the libraries for
other languages.

## Documentation

<https://docs.zevauth.com/concepts/server-sdks>

## Support

Questions and bug reports: open an issue here, or contact ZevAuth support.

## License

MIT
