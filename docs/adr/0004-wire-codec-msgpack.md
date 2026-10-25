# Wire codec: MessagePack on the WebSocket gateway (protocol v2)

The realtime gateway carries binary WebSocket frames encoded with MessagePack instead of the v1 JSON text frames. REST bodies stay JSON (axum reads and writes JSON; no reason to churn the HTTP layer), but the hot path, the server↔client stream that fans out thousands of deltas per active session, is msgpack. The wire types are unchanged: the same `protocol.rs` structs and enums serialize to msgpack via `rmp_serde`, so the contract is defined once and both sides share it. REST JSON is produced from the identical types, which keeps the per-type `serde` attributes honest under both codecs.

## Considered Options

- **JSON text frames (the v1 shape)**: zero new dependency and debuggable with a plain `websocat`. Rejected as the default: every frame re-parses string keys and the field-name overhead dominates small deltas (presence, typing, voice-state snapshots), which are the majority of gateway traffic. JSON stays for REST, where the volume is low and debuggability wins.
- **CBOR (RFC 8949)**: the other obvious binary choice and msgpack's near-twin. msgpack wins on raw size for our shapes (slightly tighter integer/str encodings) and, more importantly, `rmp_serde` is the mature, actively-maintained Rust codec with first-class `serde` integration; the CBOR crates are usable but thinner. Either would have been defensible; msgpack is the lower-risk pick.
- **A custom packed binary format**: smallest frames and fastest parse, but we would own the codec, the fuzzing, and the versioning, a poor trade for a friends-scale app. Reuse `serde` and a maintained codec and keep the format self-describing enough to debug.

## Why msgpack over JSON

- **Binary frames on a binary transport**: the gateway is already a WebSocket; binary frames carry no base64 inflation and no per-frame UTF-8 validation cost on the hot path.
- **~20-30% smaller**: against the same types serialized as JSON, msgpack frames run roughly 20-30% smaller once string keys and structural punctuation are removed. The win is largest on the small, frequent frames (presence, typing, mailbox appends) where JSON overhead is a fixed cost dwarfing the payload.
- **Transcoded from Redis JSON pub/sub without re-parsing**: the server's Redis bus is JSON (human-debuggable in `redis-cli`), and the gateway transcodes bus JSON to msgpack once per outbound frame. The wire types are the shared source of truth, so the transcode is a `serde_json::from_slice` then `rmp_serde::to_vec_named`, not hand-rolled.

## Named vs positional fields and the none-omission interaction

MessagePack can encode a struct two ways: a **positional array** (fields in declaration order, no keys) or a **named map** (field name to value). The encoders here are pinned to the named form via `rmp_serde::to_vec_named`. That choice is load-bearing, not a style preference: several `Option` fields carry `#[serde(skip_serializing_if = "Option::is_none")]`, so a `None` field is **omitted** from the frame entirely. The positional representation has no way to express "field 4 is absent"; it would either emit a hole or shift every later field, so it is incompatible with none-omission. Named encoding drops the key cleanly, and the decoders accept both named and positional input (they are codec-agnostic; only the encoders are pinned), which keeps the door open for a future compact positional mode if the optional fields are ever dropped.

`skip_serializing_if` reaches the msgpack path because it is a `serde` attribute, not a JSON one; the test `msgpack_encoding_omits_none_option_fields` pins that a `None` option leaves no trace in the frame bytes.

## v1 to v2 migration

- v1 clients and the v1 server spoke JSON text frames on the gateway at `protocol=1`.
- v2 moves the gateway to binary MessagePack frames at `protocol=2`; REST bodies are unchanged (still JSON).
- `PROTOCOL_VERSION` is `2`. The `GET /ws?token=...&protocol=<v>` upgrade rejects a mismatched `protocol` query parameter with `ErrorCode::ProtocolVersion` (HTTP-mapped 400) before the socket is accepted. There is no in-band negotiation; the version is asserted up front.

## Decision: v2 servers do NOT support v1 clients

There is no dual-stack or on-the-wire v1↔v2 negotiation. A v1 client against a v2 server is rejected at the `protocol` query parameter, not silently degraded. Rationale: the v1 install base is a single friends-scale instance with one operator, the gateway is the only v1 surface (REST JSON is unchanged), and a JSON-fallback path on the gateway would double the codec surface and the test matrix for no real users. The cost of a hard cutover is one client release coordinated with one server release; the cost of indefinite dual-stack is forever. Clients are expected to update with the server.

## Unknown variants: `Unknown` and `#[serde(other)]`

Every public wire enum (`ErrorCode`, `ChannelKind`, `MessageKind`, `CallSignalKind`, `WsClientBody`, `WsServerBody`) is `#[non_exhaustive]` and ends in a unit `Unknown` variant annotated `#[serde(other)]`. An unrecognized variant tag on the wire (a newer peer's new variant, or a malformed frame) deserializes to `Unknown` rather than returning `Err`.

This is the forward-compatibility story in lieu of a versioned schema: a newer server can emit a variant an older client does not know, and the older client absorbs it as `Unknown` and logs/ignores instead of tearing down the connection. Symmetrically the server absorbs unknown client variants. The externally-tagged msgpack representation is preserved (a unit variant is a bare tag string, a struct variant is a single-key map); `#[serde(other)]` catches any tag that matches no known variant. We deliberately did **not** switch to `#[serde(untagged)]`, which would change the wire shape and erase variant discrimination.

Obligations the policy imposes:

- Clients MUST handle `Unknown` gracefully: log and ignore, never disconnect over it.
- Servers MUST NOT rely on clients understanding newer variants; anything new may land as `Unknown` and be dropped on the other end.
- The `Unknown` variant is a read-side sink; nothing in this version serializes it on purpose.

## Consequences

- The gateway codec is `rmp_serde` (named encoding), shared by both crates via `bysyc-common`; the wire types in `protocol.rs` are the single contract for both msgpack (gateway) and JSON (REST).
- Frames are not human-readable; debugging is done via an `rmp-serde` decode or the `redis-cli` JSON bus upstream of the transcode.
- Adding a new enum variant is non-breaking for an older peer (it lands as `Unknown`); adding a new field to a struct is non-breaking as long as it is `Option` with a skip-on-none default or carries a `#[serde(default)]`. Required new fields are a breaking change and must ride a `protocol` version bump.
- v1 clients are not supported against v2 servers; the `protocol` parameter is the gate, not a hint.
