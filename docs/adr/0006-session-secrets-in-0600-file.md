# Client secrets in a 0600 file, not the OS keychain

The client's session token and Olm/Megolm pickle passphrase live in
`data_dir/secrets.json`, written with mode `0o600` on unix
(`std::os::unix::fs::PermissionsExt`), never the OS keychain. The
passphrase still never lives inside the SQLite file it protects, so the
ADR-0001 invariant (the Instance and its on-disk state never hold keys)
is kept; only the storage location of the wrapper key changes.
Accepted; supersedes the keychain clause of
[ADR-0003](0003-pure-rust-egui-client.md).

## Considered Options

- **OS keychain via the `keyring` crate** (ADR-0003's original choice):
  the right primitive in principle, but on macOS every access prompts
  the user, and the crate's cross-platform backends are uneven. The
  prompt friction is unacceptable for a chat client that reads its
  secrets on every launch.
- **A config file in `$HOME`**: prompt-free, but a fixed home-dir path
  collides across multiple Instances and is harder to scope to the
  per-Instance data dir than a file that lives inside it.

## Consequences

- The secrets file is per-data-dir, so each Instance the client
  connects to gets its own `secrets.json`; switching Instances switches
  secrets with it.
- Existing accounts that stored a passphrase in the keychain must
  re-register once: the keychain passphrase is intentionally not
  migrated (reading it would prompt again).
- `chmod 600` is unix-only; on other platforms the file is created with
  the runtime default and the operator should restrict the data dir.
