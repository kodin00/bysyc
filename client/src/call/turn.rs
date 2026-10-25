//! TURN relay client (RFC 5766) for Calls.
//!
//! str0m 0.24 ships no TURN support (its ICE engine gathers host candidates
//! only), so this module implements the client half of TURN ourselves on the
//! single call UDP socket:
//!
//! * long-term credential handshake (`401` → realm/nonce → authenticated
//!   retry with `MESSAGE-INTEGRITY` keyed on `MD5(user:realm:pass)`),
//! * one shared allocation (`XOR-RELAYED-ADDRESS` becomes the relay ICE
//!   candidate we advertise, `XOR-MAPPED-ADDRESS` the srflx one),
//! * `CreatePermission` + `ChannelBind` per peer address, `ChannelData`
//!   wrapping for outgoing relayed traffic and unwrapping for incoming,
//! * `Refresh` at half the granted lifetime.
//!
//! All crypto (MD5, SHA-1, HMAC-SHA1, CRC32) is hand-rolled and covered by
//! RFC 1321 / RFC 2202 test vectors at the bottom of this file — the crate
//! manifest is frozen for C5, so no new dependencies are allowed. The STUN
//! codec is also local: we need custom attributes (`REQUESTED-TRANSPORT`,
//! `CHANNEL-NUMBER`, …) that the `is` crate's builder does not expose.
//!
//! Methods that need to emit bytes as a side effect (`handle_input`,
//! `wrap_outgoing`, `tick`) buffer them in an internal outbox the engine
//! drains with [`TurnClient::take_sends`] after every interaction.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Crypto primitives
// ---------------------------------------------------------------------------

/// MD5 (RFC 1321).
fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    );

    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// SHA-1 (RFC 3174).
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), 0x5A82_7999),
                1 => (b ^ c ^ d, 0x6ED9_EBA1),
                2 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, hi) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&hi.to_be_bytes());
    }
    out
}

/// HMAC-SHA1 (RFC 2104).
fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..20].copy_from_slice(&sha1(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend(block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(84);
    outer.extend(block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) for STUN FINGERPRINT.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// STUN codec
// ---------------------------------------------------------------------------

const STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

// Message types: small methods, class encoded in bits 4/8 (RFC 5389 §6).
const TYPE_ALLOCATE_REQ: u16 = 0x0003;
const TYPE_ALLOCATE_OK: u16 = 0x0103;
const TYPE_REFRESH_REQ: u16 = 0x0004;
const TYPE_REFRESH_OK: u16 = 0x0104;
const TYPE_SEND_IND: u16 = 0x0016;
const TYPE_DATA_IND: u16 = 0x0017;
const TYPE_PERMISSION_REQ: u16 = 0x0008;
const TYPE_PERMISSION_OK: u16 = 0x0108;
const TYPE_BIND_REQ: u16 = 0x0009;
const TYPE_BIND_OK: u16 = 0x0109;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_FINGERPRINT: u16 = 0x8028;

/// Random 12-byte STUN transaction id (`u128` is uniform via `rand`).
fn new_trans_id() -> [u8; 12] {
    let b = rand::random::<u128>().to_be_bytes();
    [
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
    ]
}

/// Incremental STUN message builder (encoding side).
struct StunBuilder {
    msg_type: u16,
    trans_id: [u8; 12],
    attrs: Vec<u8>,
}

impl StunBuilder {
    fn new(msg_type: u16) -> Self {
        StunBuilder {
            msg_type,
            trans_id: new_trans_id(),
            attrs: Vec::new(),
        }
    }

    /// Build a request with a caller-chosen transaction id (tests).
    #[cfg(test)]
    fn with_trans_id(msg_type: u16, trans_id: [u8; 12]) -> Self {
        StunBuilder {
            msg_type,
            trans_id,
            attrs: Vec::new(),
        }
    }

    fn attr(mut self, kind: u16, value: &[u8]) -> Self {
        self.attrs.extend_from_slice(&kind.to_be_bytes());
        self.attrs
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.attrs.extend_from_slice(value);
        while !self.attrs.len().is_multiple_of(4) {
            self.attrs.push(0); // padding not counted in the length
        }
        self
    }

    fn requested_transport(self) -> Self {
        self.attr(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]) // UDP
    }

    fn lifetime(self, secs: u32) -> Self {
        self.attr(ATTR_LIFETIME, &secs.to_be_bytes())
    }

    fn xor_peer_address(self, addr: SocketAddr) -> Self {
        self.attr(ATTR_XOR_PEER_ADDRESS, &encode_xor_address(addr))
    }

    fn channel_number(self, number: u16) -> Self {
        self.attr(ATTR_CHANNEL_NUMBER, &number.to_be_bytes())
    }

    fn data(self, payload: &[u8]) -> Self {
        self.attr(ATTR_DATA, payload)
    }

    fn username(self, name: &str) -> Self {
        self.attr(ATTR_USERNAME, name.as_bytes())
    }

    fn realm(self, realm: &str) -> Self {
        self.attr(ATTR_REALM, realm.as_bytes())
    }

    fn nonce(self, nonce: &str) -> Self {
        self.attr(ATTR_NONCE, nonce.as_bytes())
    }

    fn header(&self, body_len: u16) -> Vec<u8> {
        let mut head = Vec::with_capacity(20 + self.attrs.len());
        head.extend_from_slice(&self.msg_type.to_be_bytes());
        head.extend_from_slice(&body_len.to_be_bytes());
        head.extend_from_slice(&STUN_MAGIC);
        head.extend_from_slice(&self.trans_id);
        head
    }

    /// Finish: add MESSAGE-INTEGRITY when `key` is given (HMAC over the
    /// message with the length field pointing at the end of the MI
    /// attribute), then always FINGERPRINT.
    fn finish(mut self, key: Option<&[u8]>) -> Vec<u8> {
        if let Some(key) = key {
            let head = self.header((self.attrs.len() + 24) as u16);
            let mut signed = head;
            signed.extend_from_slice(&self.attrs);
            let mac = hmac_sha1(key, &signed);
            self = self.attr(ATTR_MESSAGE_INTEGRITY, &mac);
        }

        let head = self.header((self.attrs.len() + 8) as u16);
        let mut msg = head;
        msg.extend_from_slice(&self.attrs);
        let crc = crc32(&msg) ^ 0x5354_554e;
        msg.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&crc.to_be_bytes());
        msg
    }
}

/// `XOR-*-ADDRESS` value bytes for `addr` (IPv4/IPv6, RFC 5389 §15.2).
fn encode_xor_address(addr: SocketAddr) -> Vec<u8> {
    let port = addr.port() ^ ((u16::from(STUN_MAGIC[0]) << 8) | u16::from(STUN_MAGIC[1]));
    let (family, xip): (u8, Vec<u8>) = match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            (
                0x01,
                vec![
                    o[0] ^ STUN_MAGIC[0],
                    o[1] ^ STUN_MAGIC[1],
                    o[2] ^ STUN_MAGIC[2],
                    o[3] ^ STUN_MAGIC[3],
                ],
            )
        }
        std::net::IpAddr::V6(v6) => {
            // XOR with the magic cookie plus its RFC 5389 expansion.
            let xor_key: [u8; 16] = [
                0x21,
                0x12,
                0xA4,
                0x42,
                STUN_MAGIC[0],
                STUN_MAGIC[1],
                STUN_MAGIC[2],
                STUN_MAGIC[3],
                STUN_MAGIC[0],
                STUN_MAGIC[1],
                STUN_MAGIC[2],
                STUN_MAGIC[3],
                STUN_MAGIC[0],
                STUN_MAGIC[1],
                STUN_MAGIC[2],
                STUN_MAGIC[3],
            ];
            (
                0x02,
                v6.octets()
                    .iter()
                    .zip(xor_key.iter())
                    .map(|(a, b)| a ^ b)
                    .collect(),
            )
        }
    };
    let mut out = Vec::with_capacity(4 + xip.len());
    out.push(0);
    out.push(family);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&xip);
    out
}

/// Decoded STUN message (minimal surface we need).
struct StunMsg<'a> {
    msg_type: u16,
    trans_id: [u8; 12],
    raw: &'a [u8],
    attrs_start: usize,
    body_len: usize,
}

impl<'a> StunMsg<'a> {
    fn parse(buf: &'a [u8]) -> Option<StunMsg<'a>> {
        if buf.len() < 20 || buf[0] & 0xC0 != 0 || buf[4..8] != STUN_MAGIC {
            return None;
        }
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 20 + body_len {
            return None;
        }
        let mut trans_id = [0u8; 12];
        trans_id.copy_from_slice(&buf[8..20]);
        Some(StunMsg {
            msg_type,
            trans_id,
            raw: buf,
            attrs_start: 20,
            body_len,
        })
    }

    /// Iterate `(kind, value)` over attributes (length excludes padding).
    fn attrs(&self) -> impl Iterator<Item = (u16, &'a [u8])> + '_ {
        let mut off = self.attrs_start;
        let end = self.attrs_start + self.body_len;
        let raw: &'a [u8] = self.raw;
        std::iter::from_fn(move || {
            if off + 4 > end {
                return None;
            }
            let kind = u16::from_be_bytes([raw[off], raw[off + 1]]);
            let len = u16::from_be_bytes([raw[off + 2], raw[off + 3]]) as usize;
            let vstart = off + 4;
            if vstart + len > end {
                return None;
            }
            let value = &raw[vstart..vstart + len];
            off = vstart + ((len + 3) & !3);
            Some((kind, value))
        })
    }

    fn attr(&self, want: u16) -> Option<&'a [u8]> {
        self.attrs().find(|(k, _)| *k == want).map(|(_, v)| v)
    }

    fn str_attr(&self, want: u16) -> Option<&'a str> {
        self.attr(want).and_then(|v| std::str::from_utf8(v).ok())
    }

    fn error_code(&self) -> Option<u16> {
        let v = self.attr(ATTR_ERROR_CODE)?;
        if v.len() < 4 {
            return None;
        }
        Some(u16::from(v[2]) * 100 + u16::from(v[3]))
    }

    fn xor_addr(&self, want: u16) -> Option<SocketAddr> {
        let v = self.attr(want)?;
        if v.len() < 4 {
            return None;
        }
        let port = u16::from_be_bytes([v[2], v[3]])
            ^ ((u16::from(STUN_MAGIC[0]) << 8) | u16::from(STUN_MAGIC[1]));
        let ip = match (v[1], v.len()) {
            (0x01, l) if l >= 8 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                v[4] ^ STUN_MAGIC[0],
                v[5] ^ STUN_MAGIC[1],
                v[6] ^ STUN_MAGIC[2],
                v[7] ^ STUN_MAGIC[3],
            )),
            (0x02, l) if l >= 20 => {
                let xor_key: [u8; 16] = [
                    0x21,
                    0x12,
                    0xA4,
                    0x42,
                    STUN_MAGIC[0],
                    STUN_MAGIC[1],
                    STUN_MAGIC[2],
                    STUN_MAGIC[3],
                    STUN_MAGIC[0],
                    STUN_MAGIC[1],
                    STUN_MAGIC[2],
                    STUN_MAGIC[3],
                    STUN_MAGIC[0],
                    STUN_MAGIC[1],
                    STUN_MAGIC[2],
                    STUN_MAGIC[3],
                ];
                let mut o = [0u8; 16];
                for i in 0..16 {
                    o[i] = v[4 + i] ^ xor_key[i];
                }
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(o))
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }
}

/// First byte 0x40..=0x7F ⇒ TURN ChannelData (RFC 5766 §11.4).
fn is_channel_data(buf: &[u8]) -> bool {
    matches!(buf.first(), Some(b) if (0x40..=0x7F).contains(b))
}

fn encode_channel_data(number: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_channel_data(buf: &[u8]) -> Option<(u16, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let number = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some((number, &buf[4..4 + len]))
}

// ---------------------------------------------------------------------------
// TURN client state machine
// ---------------------------------------------------------------------------

/// Allocation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllocState {
    Idle,
    Allocating,
    Ready,
    /// TURN unusable (auth rejected or no response); the Call continues
    /// with host candidates only.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReqKind {
    Allocate,
    Refresh,
    Permission,
    Bind,
}

struct PendingReq {
    kind: ReqKind,
    trans_id: [u8; 12],
    /// Authenticated variant to (re)transmit; the anonymous Allocate probe
    /// is stored here before the 401 dance.
    wire: Vec<u8>,
    sent_at: Instant,
    rto: Duration,
    attempts: u8,
}

/// A TURN-server packet carrying application data from a peer.
#[derive(Debug)]
pub struct TurnPacket {
    pub from: SocketAddr,
    pub payload: Vec<u8>,
}

const REQUESTED_LIFETIME_SECS: u32 = 600;
const MAX_ATTEMPTS: u8 = 4;
const FIRST_RTO: Duration = Duration::from_millis(500);

/// Client-side TURN allocation on the shared call socket. One instance per
/// CallSession; the engine feeds it server packets (`handle_input`), a clock
/// (`tick`), and relayed outgoing datagrams (`wrap_outgoing` — which lazily
/// drives permissions and channel binds).
pub struct TurnClient {
    server: SocketAddr,
    username: String,
    password: String,
    realm: Option<String>,
    nonce: Option<String>,
    state: AllocState,
    relay: Option<SocketAddr>,
    mapped: Option<SocketAddr>,
    lifetime: Duration,
    refresh_at: Option<Instant>,
    pending: Vec<PendingReq>,
    /// Peer IPs with a permission installed or requested (TURN permissions
    /// are per-IP, not per-port).
    perms_requested: HashSet<std::net::IpAddr>,
    /// peer address → channel number (bound or optimistically being bound).
    channel_of: HashMap<SocketAddr, u16>,
    channel_peer: HashMap<u16, SocketAddr>,
    next_channel: u16,
    /// Bytes waiting for the engine to send on the socket.
    outbox: Vec<Vec<u8>>,
}

impl TurnClient {
    pub fn new(server: SocketAddr, username: String, password: String) -> Self {
        TurnClient {
            server,
            username,
            password,
            realm: None,
            nonce: None,
            state: AllocState::Idle,
            relay: None,
            mapped: None,
            lifetime: Duration::from_secs(REQUESTED_LIFETIME_SECS as u64),
            refresh_at: None,
            pending: Vec::new(),
            perms_requested: HashSet::new(),
            channel_of: HashMap::new(),
            channel_peer: HashMap::new(),
            next_channel: 0x4000,
            outbox: Vec::new(),
        }
    }

    /// Server address packets are expected from.
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Kick off the Allocate dance.
    pub fn start(&mut self) -> Vec<Vec<u8>> {
        if self.state != AllocState::Idle {
            return Vec::new();
        }
        self.state = AllocState::Allocating;
        let (wire, id) = self.build_allocate(false);
        self.pending.push(PendingReq {
            kind: ReqKind::Allocate,
            trans_id: id,
            wire: wire.clone(),
            sent_at: Instant::now(),
            rto: FIRST_RTO,
            attempts: 1,
        });
        vec![wire]
    }

    /// Long-term-credential key: `MD5(username ":" realm ":" password)`.
    fn key(&self) -> Option<[u8; 16]> {
        let realm = self.realm.as_ref()?;
        Some(md5(format!(
            "{}:{}:{}",
            self.username, realm, self.password
        )
        .as_bytes()))
    }

    /// Extract the transaction id from a finished message.
    fn trans_id_of(msg: &[u8]) -> [u8; 12] {
        msg[8..20].try_into().unwrap()
    }

    fn build_allocate(&self, authed: bool) -> (Vec<u8>, [u8; 12]) {
        let mut b = StunBuilder::new(TYPE_ALLOCATE_REQ).requested_transport();
        if authed {
            b = b
                .lifetime(REQUESTED_LIFETIME_SECS)
                .realm(self.realm.as_deref().unwrap_or(""))
                .nonce(self.nonce.as_deref().unwrap_or(""))
                .username(&self.username);
        }
        let key = if authed { self.key() } else { None };
        let msg = b.finish(key.as_ref().map(|k| k.as_slice()));
        let id = Self::trans_id_of(&msg);
        (msg, id)
    }

    /// Handle one datagram from the TURN server. Returns unwrapped peer
    /// data when the packet was a Data indication or ChannelData; anything
    /// else (responses) updates state, possibly queueing follow-ups.
    pub fn handle_input(&mut self, buf: &[u8]) -> Option<TurnPacket> {
        if is_channel_data(buf) {
            let (number, payload) = decode_channel_data(buf)?;
            let from = *self.channel_peer.get(&number)?;
            return Some(TurnPacket {
                from,
                payload: payload.to_vec(),
            });
        }

        let msg = StunMsg::parse(buf)?;

        // Data indication: application data from a peer.
        if msg.msg_type == TYPE_DATA_IND {
            let from = msg.xor_addr(ATTR_XOR_PEER_ADDRESS)?;
            let payload = msg.attr(ATTR_DATA)?.to_vec();
            return Some(TurnPacket { from, payload });
        }

        // Otherwise: a response to one of our requests (match by trans id).
        let pos = self
            .pending
            .iter()
            .position(|p| p.trans_id == msg.trans_id)?;

        let is_success = matches!(
            msg.msg_type,
            TYPE_ALLOCATE_OK | TYPE_REFRESH_OK | TYPE_PERMISSION_OK | TYPE_BIND_OK
        );
        let error = if is_success { None } else { msg.error_code() };

        let req = self.pending.remove(pos);
        match req.kind {
            ReqKind::Allocate => self.on_allocate_response(&msg, error),
            ReqKind::Refresh => self.on_refresh_response(&msg, error),
            // Permissions/binds were installed optimistically; failures just
            // mean relayed traffic to that peer may drop until retried by
            // ICE connectivity checks.
            ReqKind::Permission | ReqKind::Bind => {}
        }
        None
    }

    fn on_allocate_response(&mut self, msg: &StunMsg, error: Option<u16>) {
        match error {
            // 401 dance (RFC 5389 long-term credential): the anonymous probe
            // was rejected carrying realm + nonce; rebuild the Allocate with
            // USERNAME/REALM/NONCE + MESSAGE-INTEGRITY keyed on
            // MD5(user:realm:pass) (see `key`). 438 (stale nonce) takes the
            // same arm — learn the fresh nonce, retry once.
            Some(401) | Some(438) => {
                if let Some(r) = msg.str_attr(ATTR_REALM) {
                    self.realm = Some(r.to_string());
                }
                if let Some(n) = msg.str_attr(ATTR_NONCE) {
                    self.nonce = Some(n.to_string());
                }
                if self.realm.is_some() && self.nonce.is_some() {
                    let (wire, id) = self.build_allocate(true);
                    self.pending.push(PendingReq {
                        kind: ReqKind::Allocate,
                        trans_id: id,
                        wire: wire.clone(),
                        sent_at: Instant::now(),
                        rto: FIRST_RTO,
                        attempts: 1,
                    });
                    self.outbox.push(wire);
                } else {
                    self.state = AllocState::Failed;
                }
            }
            Some(_) => self.state = AllocState::Failed,
            None => {
                let relay = msg.xor_addr(ATTR_XOR_RELAYED_ADDRESS);
                let mapped = msg.xor_addr(ATTR_XOR_MAPPED_ADDRESS);
                let Some(relay) = relay else {
                    self.state = AllocState::Failed;
                    return;
                };
                self.relay = Some(relay);
                self.mapped = mapped;
                let granted = msg
                    .attr(ATTR_LIFETIME)
                    .and_then(|v| v.try_into().ok())
                    .map(u32::from_be_bytes)
                    .unwrap_or(REQUESTED_LIFETIME_SECS);
                self.lifetime = Duration::from_secs(granted as u64);
                self.refresh_at = Some(Instant::now() + self.lifetime / 2);
                self.state = AllocState::Ready;
            }
        }
    }

    fn on_refresh_response(&mut self, msg: &StunMsg, error: Option<u16>) {
        if error.is_none() {
            if let Some(granted) = msg
                .attr(ATTR_LIFETIME)
                .and_then(|v| v.try_into().ok())
                .map(u32::from_be_bytes)
            {
                self.lifetime = Duration::from_secs(granted as u64);
            }
            self.refresh_at = Some(Instant::now() + self.lifetime / 2);
        } else if error == Some(438) {
            // Stale nonce: learn the fresh one and retry once.
            if let Some(n) = msg.str_attr(ATTR_NONCE) {
                self.nonce = Some(n.to_string());
            }
            if let Some(r) = msg.str_attr(ATTR_REALM) {
                self.realm = Some(r.to_string());
            }
            self.refresh_now();
        }
    }

    /// Wrap one outgoing relayed datagram. Lazily requests permission +
    /// channel bind for the peer; uses compact ChannelData once a channel
    /// is assigned (optimistically — bind success is the normal case),
    /// otherwise a Send indication (indications are not authenticated).
    pub fn wrap_outgoing(&mut self, dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
        // Was a channel already (optimistically) assigned before this call?
        // The first datagram for a peer still goes out as a Send indication;
        // once the ChannelBind request has been queued, later datagrams use
        // ChannelData.
        let had_channel = self.channel_of.contains_key(&dest);
        if !self.perms_requested.contains(&dest.ip()) {
            self.perms_requested.insert(dest.ip());
            let (wire, id) = self.authed_request(ReqKind::Permission, TYPE_PERMISSION_REQ, |b| {
                b.xor_peer_address(dest)
            });
            self.pending.push(PendingReq {
                kind: ReqKind::Permission,
                trans_id: id,
                wire: wire.clone(),
                sent_at: Instant::now(),
                rto: FIRST_RTO,
                attempts: 1,
            });
            self.outbox.push(wire);
        }

        if !self.channel_of.contains_key(&dest) && self.next_channel < 0x7FFF {
            let number = self.next_channel;
            self.next_channel += 1;
            self.channel_of.insert(dest, number);
            self.channel_peer.insert(number, dest);
            let (wire, id) = self.authed_request(ReqKind::Bind, TYPE_BIND_REQ, |b| {
                b.channel_number(number).xor_peer_address(dest)
            });
            self.pending.push(PendingReq {
                kind: ReqKind::Bind,
                trans_id: id,
                wire: wire.clone(),
                sent_at: Instant::now(),
                rto: FIRST_RTO,
                attempts: 1,
            });
            self.outbox.push(wire);
        }

        match self.channel_of.get(&dest) {
            Some(number) if had_channel => encode_channel_data(*number, payload),
            _ => StunBuilder::new(TYPE_SEND_IND)
                .xor_peer_address(dest)
                .data(payload)
                .finish(None),
        }
    }

    /// Build an authenticated request (shared shape for permission / bind /
    /// refresh / allocate-retry).
    fn authed_request(
        &self,
        _kind: ReqKind,
        msg_type: u16,
        extra: impl FnOnce(StunBuilder) -> StunBuilder,
    ) -> (Vec<u8>, [u8; 12]) {
        let mut b = extra(StunBuilder::new(msg_type));
        if let Some(r) = &self.realm {
            b = b.realm(r);
        }
        if let Some(n) = &self.nonce {
            b = b.nonce(n);
        }
        b = b.username(&self.username);
        let msg = b.finish(self.key().as_ref().map(|k| k.as_slice()));
        let id = Self::trans_id_of(&msg);
        (msg, id)
    }

    fn refresh_now(&mut self) {
        if self.pending.iter().any(|p| p.kind == ReqKind::Refresh) {
            return;
        }
        let (wire, id) = self.authed_request(ReqKind::Refresh, TYPE_REFRESH_REQ, |b| {
            b.lifetime(REQUESTED_LIFETIME_SECS)
        });
        self.pending.push(PendingReq {
            kind: ReqKind::Refresh,
            trans_id: id,
            wire: wire.clone(),
            sent_at: Instant::now(),
            rto: FIRST_RTO,
            attempts: 1,
        });
        self.outbox.push(wire);
    }

    /// Advance retransmission timers and the refresh schedule.
    pub fn tick(&mut self, now: Instant) {
        let mut allocate_expired = false;
        self.pending.retain(|req| {
            if now.duration_since(req.sent_at) >= req.rto && req.attempts >= MAX_ATTEMPTS {
                if req.kind == ReqKind::Allocate {
                    allocate_expired = true;
                }
                return false;
            }
            true
        });
        if allocate_expired && self.state == AllocState::Allocating {
            self.state = AllocState::Failed;
            self.pending.clear();
            return;
        }
        for req in self.pending.iter_mut() {
            if now.duration_since(req.sent_at) >= req.rto {
                self.outbox.push(req.wire.clone());
                req.attempts += 1;
                req.sent_at = now;
                req.rto = (req.rto * 2).min(Duration::from_secs(4));
            }
        }
        if self.state == AllocState::Ready && self.refresh_at.is_some_and(|at| now >= at) {
            self.refresh_now();
        }
    }

    /// Relay address (`XOR-RELAYED-ADDRESS`) for the `typ relay` candidate.
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.relay
    }

    /// Server-reflexive address for the `typ srflx` candidate.
    pub fn mapped_addr(&self) -> Option<SocketAddr> {
        self.mapped
    }

    pub fn ready(&self) -> bool {
        self.state == AllocState::Ready
    }

    pub fn failed(&self) -> bool {
        self.state == AllocState::Failed
    }

    /// Drain bytes queued by side effects; the engine sends these to the
    /// TURN server on the call socket.
    pub fn take_sends(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox)
    }
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Hand-assemble a STUN response with arbitrary attributes.
    fn response(msg_type: u16, trans_id: [u8; 12], attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in attrs {
            body.extend_from_slice(&k.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&msg_type.to_be_bytes());
        msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
        msg.extend_from_slice(&STUN_MAGIC);
        msg.extend_from_slice(&trans_id);
        msg.extend_from_slice(&body);
        msg
    }

    /// Allocate error response type — the server side of the exchange; the
    /// client only ever receives these, never sends them.
    const TYPE_ALLOCATE_ERR: u16 = 0x0113;
    /// Refresh error response type (RFC 5389: error = request | 0x0110).
    const TYPE_REFRESH_ERR: u16 = 0x0114;

    /// Append an ERROR-CODE attribute. The builder proper has no such
    /// method (the client never emits STUN errors); tests synthesize the
    /// server's side of the 401/403 dance with this extension.
    trait StunErrorCode {
        fn error_code(self, code: u16, reason: &str) -> Self;
    }

    impl StunErrorCode for StunBuilder {
        fn error_code(self, code: u16, reason: &str) -> Self {
            let class = (code / 100) as u8;
            let number = (code % 100) as u8;
            let mut v = vec![0, 0, class, number];
            v.extend_from_slice(reason.as_bytes());
            self.attr(ATTR_ERROR_CODE, &v)
        }
    }

    #[test]
    fn md5_rfc1321_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
    }

    #[test]
    fn sha1_rfc3174_vectors() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha1(&million_a)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_vectors() {
        assert_eq!(
            hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&hmac_sha1(&[0xaa; 20], &[0xdd; 50])),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
        // Key longer than the block size exercises key hashing.
        assert_eq!(
            hex(&hmac_sha1(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    #[test]
    fn crc32_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn long_term_key_is_md5_of_triple() {
        let mut c = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "maTCh".into(),
            "matcha".into(),
        );
        c.realm = Some("example.org".into());
        assert_eq!(c.key().unwrap(), md5(b"maTCh:example.org:matcha"));
    }

    #[test]
    fn allocate_request_is_wellformed_stun() {
        let mut c = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "bysyc".into(),
            "pw".into(),
        );
        c.realm = Some("bysyc".into());
        c.nonce = Some("n1".into());
        let (msg, id) = c.build_allocate(true);
        let parsed = StunMsg::parse(&msg).unwrap();
        assert_eq!(parsed.trans_id, id);
        assert_eq!(parsed.msg_type, TYPE_ALLOCATE_REQ);
        assert!(parsed.attr(ATTR_MESSAGE_INTEGRITY).is_some());
        assert!(parsed.attr(ATTR_REQUESTED_TRANSPORT).is_some());
        assert_eq!(parsed.str_attr(ATTR_REALM), Some("bysyc"));
        // FINGERPRINT validates: CRC over the message minus the last 8
        // bytes, with the header length covering the fingerprint attribute.
        let end = 20 + parsed.body_len;
        assert_eq!(msg.len(), end);
        let mut head = msg[..end - 8].to_vec();
        let len = (end as u16 - 20).to_be_bytes();
        head[2] = len[0];
        head[3] = len[1];
        let stored = u32::from_be_bytes(msg[end - 4..end].try_into().unwrap());
        assert_eq!(crc32(&head) ^ 0x5354_554e, stored);

        // The anonymous probe carries no MESSAGE-INTEGRITY.
        let (anon, _) = {
            let c2 = TurnClient::new(
                "127.0.0.1:3478".parse().unwrap(),
                "bysyc".into(),
                "pw".into(),
            );
            c2.build_allocate(false)
        };
        assert!(
            StunMsg::parse(&anon)
                .unwrap()
                .attr(ATTR_MESSAGE_INTEGRITY)
                .is_none()
        );
    }

    #[test]
    fn xor_address_roundtrip() {
        let addrs: [SocketAddr; 5] = [
            "1.2.3.4:4433".parse().unwrap(),
            "255.255.255.255:65535".parse().unwrap(),
            "0.0.0.0:0".parse().unwrap(),
            "[::1]:3478".parse().unwrap(),
            "[2001:db8::1234]:9999".parse().unwrap(),
        ];
        for addr in addrs {
            let msg = StunBuilder::with_trans_id(TYPE_SEND_IND, [7u8; 12])
                .xor_peer_address(addr)
                .finish(None);
            assert_eq!(
                StunMsg::parse(&msg)
                    .unwrap()
                    .xor_addr(ATTR_XOR_PEER_ADDRESS),
                Some(addr)
            );
        }
    }

    #[test]
    fn channel_data_roundtrip() {
        let payload = vec![1u8, 2, 3, 4, 5];
        let wire = encode_channel_data(0x4001, &payload);
        assert!(is_channel_data(&wire));
        assert!(!is_channel_data(&[0x00, 0x01, 0x00, 0x00]));
        let (num, data) = decode_channel_data(&wire).unwrap();
        assert_eq!(num, 0x4001);
        assert_eq!(data, &payload[..]);
    }

    #[test]
    fn allocate_401_dance_then_success() {
        let mut client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "bysyc".into(),
            "secret".into(),
        );
        let msgs = client.start();
        assert_eq!(msgs.len(), 1);
        assert_eq!(client.state, AllocState::Allocating);

        // 401 with realm + nonce, echoing our transaction id.
        let req = StunMsg::parse(&msgs[0]).unwrap();
        let err = StunBuilder::with_trans_id(TYPE_ALLOCATE_ERR, req.trans_id)
            .error_code(401, "Unauthorized")
            .realm("bysyc")
            .nonce("n-abc")
            .finish(None);
        assert!(client.handle_input(&err).is_none());
        assert_eq!(client.realm.as_deref(), Some("bysyc"));
        assert_eq!(client.nonce.as_deref(), Some("n-abc"));
        let retry = client.take_sends();
        assert_eq!(retry.len(), 1);
        let authed = StunMsg::parse(&retry[0]).unwrap();
        assert!(authed.attr(ATTR_MESSAGE_INTEGRITY).is_some());

        // Success with relay + mapped + lifetime.
        let relay: SocketAddr = "198.51.100.7:49160".parse().unwrap();
        let mapped: SocketAddr = "203.0.113.9:51234".parse().unwrap();
        let ok = response(
            TYPE_ALLOCATE_OK,
            authed.trans_id,
            &[
                (ATTR_XOR_RELAYED_ADDRESS, encode_xor_address(relay)),
                (ATTR_XOR_MAPPED_ADDRESS, encode_xor_address(mapped)),
                (ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
        );
        assert!(client.handle_input(&ok).is_none());
        assert!(client.ready());
        assert_eq!(client.relay_addr(), Some(relay));
        assert_eq!(client.mapped_addr(), Some(mapped));
    }

    #[test]
    fn allocate_auth_rejected_fails_gracefully() {
        let mut client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "bysyc".into(),
            "wrong".into(),
        );
        let msgs = client.start();
        let req = StunMsg::parse(&msgs[0]).unwrap();
        let err401 = StunBuilder::with_trans_id(TYPE_ALLOCATE_ERR, req.trans_id)
            .error_code(401, "Unauthorized")
            .realm("bysyc")
            .nonce("n1")
            .finish(None);
        client.handle_input(&err401);
        let sends = client.take_sends();
        let retry = StunMsg::parse(&sends[0]).unwrap();
        let err403 = StunBuilder::with_trans_id(TYPE_ALLOCATE_ERR, retry.trans_id)
            .error_code(403, "Forbidden")
            .realm("bysyc")
            .nonce("n1")
            .finish(None);
        client.handle_input(&err403);
        assert!(client.failed());
        assert!(!client.ready());
    }

    #[test]
    fn wrap_outgoing_indication_then_channel() {
        let mut c = TurnClient::new("127.0.0.1:3478".parse().unwrap(), "u".into(), "p".into());
        c.realm = Some("r".into());
        c.nonce = Some("n".into());
        c.state = AllocState::Ready;
        let peer: SocketAddr = "10.0.0.5:50000".parse().unwrap();

        // First wrap: no channel yet → unauthenticated Send indication.
        let first = c.wrap_outgoing(peer, b"hello");
        assert_eq!(StunMsg::parse(&first).unwrap().msg_type, TYPE_SEND_IND);
        assert_eq!(
            StunMsg::parse(&first).unwrap().attr(ATTR_DATA),
            Some(&b"hello"[..])
        );
        // Permission + bind requests were queued.
        let queued = c.take_sends();
        assert_eq!(queued.len(), 2);

        // Channel assigned optimistically; second wrap uses ChannelData.
        let second = c.wrap_outgoing(peer, b"world!");
        assert!(is_channel_data(&second));
        let (num, data) = decode_channel_data(&second).unwrap();
        assert_eq!(num, 0x4000);
        assert_eq!(data, b"world!");

        // Incoming ChannelData unwraps to the peer.
        let back = encode_channel_data(num, b"reply");
        match c.handle_input(&back) {
            Some(TurnPacket { from, payload }) => {
                assert_eq!(from, peer);
                assert_eq!(payload, b"reply");
            }
            other => panic!("expected data packet, got {other:?}"),
        }
    }

    #[test]
    fn data_indication_unwraps() {
        let mut c = TurnClient::new("127.0.0.1:3478".parse().unwrap(), "u".into(), "p".into());
        let peer: SocketAddr = "10.1.2.3:4444".parse().unwrap();
        let ind = StunBuilder::new(TYPE_DATA_IND)
            .xor_peer_address(peer)
            .data(b"payload!")
            .finish(None);
        match c.handle_input(&ind) {
            Some(TurnPacket { from, payload }) => {
                assert_eq!(from, peer);
                assert_eq!(payload, b"payload!");
            }
            other => panic!("expected data packet, got {other:?}"),
        }
    }

    #[test]
    fn trans_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(new_trans_id()));
        }
    }

    /// Full TURN client lifecycle end to end: the 401 realm/nonce dance, a
    /// successful Allocate (relay + mapped + lifetime), ChannelBind setup
    /// (permission + bind wires, then their OK responses), a ChannelData
    /// round-trip, a Refresh triggered at half-lifetime, and the RFC 5389
    /// 438-stale-nonce retry path that learns a fresh nonce and re-queues.
    #[test]
    fn full_lifecycle_allocate_bind_channeldata_refresh_438() {
        let mut c = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "bysyc".into(),
            "secret".into(),
        );

        // ---- allocate: anonymous probe → 401 dance → success --------------
        let msgs = c.start();
        assert_eq!(msgs.len(), 1);
        assert_eq!(c.state, AllocState::Allocating);
        let probe = StunMsg::parse(&msgs[0]).unwrap();
        let err401 = StunBuilder::with_trans_id(TYPE_ALLOCATE_ERR, probe.trans_id)
            .error_code(401, "Unauthorized")
            .realm("bysyc")
            .nonce("n-1")
            .finish(None);
        assert!(c.handle_input(&err401).is_none());
        assert_eq!(c.realm.as_deref(), Some("bysyc"));
        assert_eq!(c.nonce.as_deref(), Some("n-1"));
        let sends = c.take_sends();
        let retry = StunMsg::parse(&sends[0]).unwrap();
        let relay: SocketAddr = "198.51.100.7:49160".parse().unwrap();
        let mapped: SocketAddr = "203.0.113.9:51234".parse().unwrap();
        let ok = response(
            TYPE_ALLOCATE_OK,
            retry.trans_id,
            &[
                (ATTR_XOR_RELAYED_ADDRESS, encode_xor_address(relay)),
                (ATTR_XOR_MAPPED_ADDRESS, encode_xor_address(mapped)),
                (ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
        );
        assert!(c.handle_input(&ok).is_none());
        assert!(c.ready());
        assert_eq!(c.relay_addr(), Some(relay));
        assert_eq!(c.mapped_addr(), Some(mapped));

        // ---- channel-bind: first wrap queues permission + bind; the first
        // datagram rides a Send indication, later ones ChannelData. --------
        let peer: SocketAddr = "10.9.8.7:50000".parse().unwrap();
        let first = c.wrap_outgoing(peer, b"hello");
        assert_eq!(StunMsg::parse(&first).unwrap().msg_type, TYPE_SEND_IND);
        let queued = c.take_sends();
        assert_eq!(queued.len(), 2, "permission + bind wires");
        let perm = StunMsg::parse(&queued[0]).unwrap();
        assert_eq!(perm.msg_type, TYPE_PERMISSION_REQ);
        let bind = StunMsg::parse(&queued[1]).unwrap();
        assert_eq!(bind.msg_type, TYPE_BIND_REQ);
        // Complete both so the pending list is empty before the refresh step
        // (otherwise tick would retransmit them, not queue a Refresh).
        assert!(c
            .handle_input(&response(TYPE_PERMISSION_OK, perm.trans_id, &[]))
            .is_none());
        assert!(c
            .handle_input(&response(TYPE_BIND_OK, bind.trans_id, &[]))
            .is_none());

        // ---- ChannelData round-trip: outgoing wraps compactly, incoming
        // unwraps to the peer address bound above. -------------------------
        let second = c.wrap_outgoing(peer, b"world");
        assert!(is_channel_data(&second));
        let (num, data) = decode_channel_data(&second).unwrap();
        assert_eq!(num, 0x4000);
        assert_eq!(data, b"world");
        let back = encode_channel_data(num, b"reply");
        match c.handle_input(&back) {
            Some(TurnPacket { from, payload }) => {
                assert_eq!(from, peer);
                assert_eq!(payload, b"reply");
            }
            other => panic!("expected ChannelData packet, got {other:?}"),
        }

        // ---- refresh: tick past refresh_at (lifetime/2) queues a Refresh
        // request built with the realm + nonce learned at allocate time. ---
        let later = Instant::now() + Duration::from_secs(400);
        c.tick(later);
        let sends = c.take_sends();
        assert_eq!(sends.len(), 1, "exactly the Refresh request");
        let refresh = StunMsg::parse(&sends[0]).unwrap();
        assert_eq!(refresh.msg_type, TYPE_REFRESH_REQ);
        assert_eq!(refresh.str_attr(ATTR_NONCE), Some("n-1"));

        // ---- 438 stale nonce: the retry learns the fresh nonce and
        // re-queues exactly one Refresh request carrying it. ---------------
        let err438 = StunBuilder::with_trans_id(TYPE_REFRESH_ERR, refresh.trans_id)
            .error_code(438, "Stale Nonce")
            .realm("bysyc")
            .nonce("n-fresh")
            .finish(None);
        assert!(c.handle_input(&err438).is_none());
        let retry_sends = c.take_sends();
        assert_eq!(retry_sends.len(), 1, "438 triggers exactly one retry");
        let retry_refresh = StunMsg::parse(&retry_sends[0]).unwrap();
        assert_eq!(retry_refresh.msg_type, TYPE_REFRESH_REQ);
        assert_eq!(
            retry_refresh.str_attr(ATTR_NONCE),
            Some("n-fresh"),
            "the retry must carry the nonce from the 438 response"
        );

        // A successful retry closes the loop and reschedules the refresh.
        let ok_refresh = response(
            TYPE_REFRESH_OK,
            retry_refresh.trans_id,
            &[(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec())],
        );
        assert!(c.handle_input(&ok_refresh).is_none());
        assert!(c.ready());
    }
}
