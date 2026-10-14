# Calls: full-mesh WebRTC with TURN relay fallback, capped at 6, audio-only

Group and private calls are E2EE by construction: WebRTC full-mesh (DTLS-SRTP peer-to-peer) so no server component ever sees media. A coturn TURN container in the compose stack relays already-encrypted packets for peers behind hard NATs — the "user ↔ server ↔ user" path — without decryption. Voice is capped at 6 participants per call and audio-only for v1; mesh upload cost for voice is trivial (~40 kbps × 5 streams) — the topology only breaks down with video.

## Considered Options

- **SFU (self-hosted LiveKit)**: scales to large groups and video, but is a Go service, E2EE through an SFU requires SFrame key handling, and it is heavy for friends-scale. Deferred to v2 alongside video/screenshare.
- **Forced relay** (all media through the server): most compatible, always works, but pays server bandwidth for every call even when direct P2P is possible. We get it as TURN fallback instead.

## Consequences

- Client WebRTC stack: str0m (sans-I/O, active, we own the UDP loop — fits tokio); audio via cpal + Opus.
- The 6-participant cap is a protocol-level limit, not a soft suggestion, until an SFU exists.
