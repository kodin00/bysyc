# E2EE via vodozemac: Olm for DMs, Megolm for channels

We need strong end-to-end encryption: the Instance stores only ciphertext for message content and file bytes, while metadata (membership, timestamps, sizes) remains server-visible. We chose vodozemac (Matrix's crypto, standalone-usable, pure Rust): Olm double-ratchet for DMs with prekey bootstrap so a DM can start while the peer is offline, and per-sender Megolm sessions for Text Channels, with session keys distributed pairwise over Olm-encrypted control messages (the WhatsApp sender-key model).

## Considered Options

- **OpenMLS (RFC 9420)**: the forward-looking standard (Discord's DAVE builds on it), but the app must implement delivery-service and identity-validation semantics itself — meaningfully more work and sharper edges. A later migration would be a rewrite-level change but is not blocked by this choice.
- **TLS + server-side encryption**: rejected outright — the server would see all content, which contradicts the product promise.

## Consequences

- No server-side thumbnails, previews, virus scanning, or content search — all such processing is client-side, post-decrypt.
- Members joining a Channel can only decrypt from their join point onward; we do not hand out earlier Megolm session keys.
- One device per Account in v1; key export is the reinstall/recovery story.
