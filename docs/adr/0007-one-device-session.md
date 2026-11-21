# One session per account (single-device model)

An Account holds at most one live session token at a time. `session::create`
records the account's current token under the per-account Redis pointer
`sessacct:{account_id}` and, before minting a new token, deletes the prior
session that pointer referenced (`DEL sess:{prior}`). A second login on the
same account therefore invalidates the first: the old token returns 401 on
`/auth/me` (and any other authenticated route) while the new token still
works. `validate` is unchanged; logout (`session::delete`) and the
`sessinfo:{account_id}` AccountInfo cache path are unchanged.

## Considered Options

- **Multiple sessions per account (the prior behavior)**: every login
  mints a fresh token and leaves older ones live. Convenient for
  multi-device use, but invalidation must move somewhere else (explicit
  logout, a revocation list, TTL expiry) and the lack of a single "current
  session" makes security event responses awkward.
- **A revocation list under `sessrev:{token}`**: let old tokens live but
  reject any present on the list. Same wire effect (old device 401s) but
  keeps an unbounded deny-list in Redis and adds a `SISMEMBER` to the
  `validate` hot path — strictly more state and work for the same outcome.

## Consequences

- One device per Account in v1: logging in elsewhere logs you out here.
  Aligned with ADR-0001's "one device per Account" recovery story (key
  export is the reinstall/recovery path).
- The `sessacct:{account_id}` pointer carries the same 30-day TTL as the
  session, so a stale pointer cannot outlive its token.
- Concurrency note on `create`: a GETDEL on the pointer followed by the
  new-SET/DEL pipeline is not a single atomic transaction, so two
  simultaneous logins on the same account can race — the surviving token is
  the one whose SET lands last, which is the desired outcome (the most
  recent login wins). No correctness loss: the loser's token is the one
  the winner's later DELETE removes (or it simply never existed in the
  pointer), and no account ever ends with two live tokens.
