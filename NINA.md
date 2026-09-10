# Go-Libsodium

Read [readme.md](readme.md) for the public API, ciphertext compatibility, key-chain
policy, and Linux secret-loader behavior before changing those boundaries.

## Initialization

`Init` owns native initialization through `sync.OnceFunc` and publishes readiness
with an atomic Boolean. Native results 0 and 1 both mean success; a negative
result panics and that failure is replayed to subsequent callers. Cryptographic
APIs retain their explicit use-before-init rejection. Do not add caller-owned
initialization locks or silently initialize inside unrelated APIs.

`StreamChunkSize` remains caller-configurable, not concurrently mutable. Set it
before concurrent stream operations. Initialization safety does not change the
ciphertext format or make arbitrary shared-buffer/configuration mutations safe.

## Validation

Run `GOTOOLCHAIN=local bash bin/check.sh`, `go test -cover ./...`, and
`go test -race ./...`. All nine Go analysis tools listed in the script's
prerequisite loop must already be on PATH; it fails before checks when any is
missing and never installs tools. Initialization regressions use fresh processes;
the native-prior-initialization fixture builds against the installed libsodium
without modifying or replacing it.
