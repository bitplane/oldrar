# Release helpers. The pushed tag triggers the release workflow, which
# publishes the crate, binaries, and GitHub release after CI passes.

check:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test --all-targets --locked
    cargo package --locked

# Bump the version (patch/minor/major or X.Y.Z), commit, tag vX.Y.Z and push.
release level="patch":
    cargo release {{level}} --execute --no-confirm
