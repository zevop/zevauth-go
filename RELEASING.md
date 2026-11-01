# Releasing

A Go module version is a git tag, so there is no registry account,
token or upload: pushing the tag is the release.

## Cutting a release

1. Set the new version in `client.go` (`const Version`, which the API
   client sends in its user agent) and commit to `main`. Let the **CI**
   workflow pass.
2. Tag and push the tag:

   ```sh
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

   Or on GitHub: **Releases → Draft a new release → Choose a tag**, type
   `v0.2.0`, target `main`, and publish.

The **Release** workflow checks the tag matches `Version`, runs the
tests, writes the GitHub Release with generated notes, and asks
proxy.golang.org to fetch the new version so `go get` sees it at once.
pkg.go.dev picks up the documentation shortly after.

The module proxy caches a version forever. Never move or re-push a tag
that has been fetched; if a release is wrong, release the next version
and add a `retract` directive for the bad one in `go.mod`.

A major version 2 or later needs the `/v2` suffix in the module path
(`github.com/zevop/zevauth-go/v2`); that is a breaking change to every
import and should be planned as one.

## One-time setup

None. The repository is public and the proxy reads it directly.
