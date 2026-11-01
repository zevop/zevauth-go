#!/usr/bin/env sh
# Copies the shared conformance fixtures from zevauth-sdk into testdata/.
# The fixtures are the executable half of the server SDK contract:
# https://github.com/zevop/zevauth-sdk/tree/main/spec
#
#   ./scripts/sync-fixtures.sh [path-to-zevauth-sdk]
set -eu
SDK="${1:-../zevauth-sdk}"
SRC="$SDK/spec/fixtures"
[ -d "$SRC" ] || { echo "No fixtures at $SRC" >&2; exit 1; }
cd "$(dirname "$0")/.."
for f in tokens.json bearer.json webhooks.json api-errors.json bridge.json discovery.json jwks.json jwks-rotated.json; do
  cp "$SRC/$f" "testdata/$f"
done
echo "Fixtures synced from $SRC"
