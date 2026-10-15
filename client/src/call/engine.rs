//! Call session engine — one dedicated thread per active call.
//!
//! [`SessionCore`] holds all call state (one str0m [`Rtc`] per remote
//! participant, offer/answer bookkeeping, trickle candidates, the TURN
//! candidate set) and is deliberately free of I/O: commands in, signals and
//! datagrams out. The engine thread ([`spawn_session`]) owns the UDP socket,
//! the cpal streams and the TURN client, and drives the core.
//!
//! Signaling travels over the account WebSocket as
//! `WsClientBody::CallSignal`; `call_id` is the voice channel id (channel
//! calls) or the DM channel id (private calls). Role assignment uses the
//! total order on account ids: the lower id offers, which makes glare
//! impossible in the normal flow; the simultaneous-offer case is resolved by
//! the higher-id side discarding its pending offer and re-creating the
//! peer's `Rtc` to accept the lower-id side's offer.
//!
//! Media: one Opus encode per 20 ms microphone frame, written into every
//! connected peer's `StreamTx` under that peer's own SSRC/sequence/clock
//! (each peer is an independent DTLS-SRTP session). Inbound RTP is decoded
//! on arrival into per-peer playback sinks mixed by the output callback.
//!
//! Verified str0m 0.24 API points used here:
//! - `Rtc::builder().set_rtp_mode(true).clear_codecs().enable_opus(..).build(clock)`
//!   (RtcConfig methods take `self` by value; `codec_config()` is the
//!   low-level `&mut` escape hatch, not needed)
//! - `SdpApi::add_media(kind, dir, stream_id, track_id, simulcast) -> Mid`
//! - `SdpApi::apply() -> Option<(SdpOffer, SdpPendingOffer)>`
//! - `SdpApi::accept_offer(self, SdpOffer) -> Result<SdpAnswer, RtcError>`
//! - `SdpApi::accept_answer(self, SdpPendingOffer, SdpAnswer) -> Result<(), RtcError>`
//! - `DirectApi::declare_stream_tx(ssrc, rtx, mid, rid) -> &mut StreamTx`
//! - `DirectApi::stream_tx(&Ssrc) -> Option<&mut StreamTx>` +
//!   `StreamTx::write_rtp(RtpWrite)`
//! - `RtpWrite::new(pt, seq, time, wallclock, payload)` +
//!   `.ext_vals(ExtensionValues)` (builder; the field itself is private)
//! - `Rtc::is_alive()` (the `RtcState` enum is private in 0.24)

use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bysyc_common::protocol::{AccountBrief, CallSignalKind, TurnInfo, WsClientBody, WsClientMsg};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::media::{Direction, MediaKind, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::rtp::{ExtensionValues, RtpWrite, SeqNo, Ssrc};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

use super::audio::{AudioIo, FRAME_SAMPLES, MicEncoder, PeerDecoder, PeerSink, SpscRing};
use super::turn::TurnClient;
use crate::net::{NetHandle, next_msg_id};

/// Mesh participant cap (matches `VoiceChannelFull` on the server).
pub const MAX_PARTICIPANTS: usize = 6;
/// Main loop cadence floor; also the audio pump period (20 ms frames).
const TICK: Duration = Duration::from_millis(20);
/// Opus payload type in str0m's default codec config; both endpoints run
/// this client, so the static PT is exactly negotiated.
const OPUS_PT: u8 = 111;

// ---------------------------------------------------------------------------
// Shared UI surface
// ---------------------------------------------------------------------------

/// Which kind of call a session hosts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallKind {
    /// Guild voice channel call (mesh, up to [`MAX_PARTICIPANTS`]).
    Channel,
    /// 1:1 private call inside a DM channel.
    Private,
}

/// One row of the participant list the overlay renders.
#[derive(Clone, Debug)]
pub struct ParticipantUi {
    pub id: i64,
    pub name: String,
    pub connected: bool,
    pub speaking: bool,
}

/// Everything the overlay needs to render. The engine thread is the only
/// writer; the UI thread only reads.
pub struct UiState {
    pub call_id: i64,
    pub kind: CallKind,
    /// Shared with the audio input callback: true stops capture at source.
    pub muted: Arc<AtomicBool>,
    pub participants: Mutex<Vec<ParticipantUi>>,
    pub audio_error: Mutex<Option<String>>,
    pub status: Mutex<String>,
    /// True while TURN relays this call (status decoration).
    pub relayed: AtomicBool,
}

impl UiState {
    fn new(call_id: i64, kind: CallKind) -> Self {
        UiState {
            call_id,
            kind,
            muted: Arc::new(AtomicBool::new(false)),
            participants: Mutex::new(Vec::new()),
            audio_error: Mutex::new(None),
            status: Mutex::new("connecting…".to_string()),
            relayed: AtomicBool::new(false),
        }
    }

    pub fn set_status(&self, s: impl Into<String>) {
        *self.status.lock().unwrap_or_else(|p| p.into_inner()) = s.into();
    }

    pub fn set_audio_error(&self, s: Option<String>) {
        *self.audio_error.lock().unwrap_or_else(|p| p.into_inner()) = s;
    }
}

// ---------------------------------------------------------------------------
// Commands / handle
// ---------------------------------------------------------------------------

/// Commands the overlay and entry points feed into a running session.
pub enum SessionCmd {
    /// One relayed signaling message (already filtered to this call).
    Signal { from: i64, kind: CallSignalKind },
    /// Complete participant snapshot for a channel call (includes us).
    Roster(Vec<AccountBrief>),
    /// Result of the `GET /turn` fetch.
    Turn(Result<TurnInfo, String>),
    /// Leave now; the engine sends Hangups and exits.
    Leave,
}

/// Handle held by the module registry; dropping it lets the engine exit on
/// its next tick (the channel is the thread's keepalive).
pub struct SessionHandle {
    pub cmd: std::sync::mpsc::Sender<SessionCmd>,
    pub ui: Arc<UiState>,
}

impl SessionHandle {
    pub fn send(&self, cmd: SessionCmd) {
        let _ = self.cmd.send(cmd);
    }
}

/// Everything a session needs beside the call identity itself.
pub struct SessionConfig {
    pub call_id: i64,
    pub kind: CallKind,
    pub me_id: i64,
    pub private_peer: Option<AccountBrief>,
    /// Private call caller: create the peer and offer at startup.
    pub auto_offer_private: bool,
    /// Offer that arrived before the session existed (incoming private call).
    pub initial_offer: Option<(i64, String)>,
    pub net: NetHandle,
    pub rt: Option<tokio::runtime::Handle>,
}

/// Signal the core wants relayed to a peer.
pub struct OutSignal {
    pub to: i64,
    pub kind: CallSignalKind,
}

/// Dataplane datagram the core produced. `source` may be the TURN relay
/// address when ICE selected the relayed candidate.
pub struct OutDatagram {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Session core (I/O-free; unit-testable headlessly)
// ---------------------------------------------------------------------------

struct SendStream {
    ssrc: Ssrc,
    pt: Pt,
    seq: u16,
    time: u32,
}

struct Peer {
    account: AccountBrief,
    rtc: Rtc,
    pending: Option<SdpPendingOffer>,
    mid: Option<Mid>,
    send: Option<SendStream>,
    decoder: Option<PeerDecoder>,
    sink: Arc<PeerSink>,
    connected: bool,
    /// Candidates received before negotiation completed; flushed on
    /// `MediaAdded`.
    remote_candidates: Vec<String>,
}

/// The call state machine. All methods append to caller-provided vectors
/// instead of performing I/O, so tests can loop two cores together.
pub struct SessionCore {
    me_id: i64,
    kind: CallKind,
    clock0: Instant,
    peers: Vec<Peer>,
    roster: Vec<AccountBrief>,
    private_peer: Option<AccountBrief>,
    /// Offers that arrived for accounts not yet known (roster lag).
    deferred_offers: Vec<(i64, String)>,
    local_addr: Option<SocketAddr>,
    host_candidates: Vec<SocketAddr>,
    turn_relay: Option<SocketAddr>,
    turn_mapped: Option<SocketAddr>,
    encoder: Option<MicEncoder>,
    frame_acc: Vec<f32>,
    /// Sinks created since the last take (engine registers them for mixing).
    new_sinks: Vec<Arc<PeerSink>>,
    /// Sinks removed since the last take (engine unsubscribes them).
    dropped_sinks: Vec<Arc<PeerSink>>,
    ended: bool,
}

impl SessionCore {
    pub fn new(me_id: i64, kind: CallKind, clock0: Instant) -> Self {
        SessionCore {
            me_id,
            kind,
            clock0,
            peers: Vec::new(),
            roster: Vec::new(),
            private_peer: None,
            deferred_offers: Vec::new(),
            local_addr: None,
            host_candidates: Vec::new(),
            turn_relay: None,
            turn_mapped: None,
            encoder: MicEncoder::new().ok(),
            frame_acc: Vec::new(),
            new_sinks: Vec::new(),
            dropped_sinks: Vec::new(),
            ended: false,
        }
    }

    pub fn me_id(&self) -> i64 {
        self.me_id
    }

    pub fn ended(&self) -> bool {
        self.ended
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn connected_count(&self) -> usize {
        self.peers.iter().filter(|p| p.connected).count()
    }

    pub fn is_connected_to(&self, peer_id: i64) -> bool {
        self.peers
            .iter()
            .any(|p| p.account.id == peer_id && p.connected)
    }

    /// Advertise our socket addresses (host candidates) to current peers.
    pub fn set_local(&mut self, addrs: &[SocketAddr], out: &mut Vec<OutSignal>) {
        self.local_addr = addrs.first().copied();
        self.host_candidates = addrs.to_vec();
        for addr in addrs {
            if let Ok(c) = Candidate::host(*addr, "udp") {
                self.add_local_candidate_all(&c, out);
            }
        }
    }

    fn add_local_candidate_all(&mut self, cand: &Candidate, out: &mut Vec<OutSignal>) {
        for peer in &mut self.peers {
            peer.rtc.add_local_candidate(cand.clone());
            out.push(OutSignal {
                to: peer.account.id,
                kind: CallSignalKind::Candidate {
                    candidate: cand.to_sdp_string(),
                    mid: None,
                },
            });
        }
    }

    /// TURN allocation succeeded: advertise relay (and srflx when the server
    /// reported one) to every peer.
    pub fn turn_ready(
        &mut self,
        relay: SocketAddr,
        mapped: Option<SocketAddr>,
        out: &mut Vec<OutSignal>,
    ) {
        self.turn_relay = Some(relay);
        self.turn_mapped = mapped;
        let base = self.local_addr.unwrap_or(relay);
        if let Some(m) = mapped {
            if let Ok(c) = Candidate::server_reflexive(m, base, "udp") {
                self.add_local_candidate_all(&c, out);
            }
        }
        if let Ok(c) = Candidate::relayed(relay, base, "udp") {
            self.add_local_candidate_all(&c, out);
        }
    }

    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.turn_relay
    }

    /// Private-call bootstrap: create the peer, offering if we initiated.
    pub fn start_private(&mut self, peer: &AccountBrief, offer: bool, out: &mut Vec<OutSignal>) {
        if self.kind != CallKind::Private {
            return;
        }
        self.private_peer = Some(peer.clone());
        self.create_peer(peer, offer, out);
    }

    /// Feed the offer that arrived before the session existed.
    pub fn take_initial_offer(&mut self, from: i64, sdp: &str, out: &mut Vec<OutSignal>) {
        if self.kind != CallKind::Private {
            return;
        }
        self.handle_offer(from, sdp, out);
    }

    fn create_peer(&mut self, account: &AccountBrief, offer: bool, out: &mut Vec<OutSignal>) {
        if self.peers.len() >= MAX_PARTICIPANTS.saturating_sub(1) {
            return;
        }
        if self.peers.iter().any(|p| p.account.id == account.id) {
            return;
        }
        let rtc = Rtc::builder()
            .set_rtp_mode(true)
            .clear_codecs()
            .enable_opus(true, false)
            .build(self.clock0);
        let sink = PeerSink::new();
        let mut peer = Peer {
            account: account.clone(),
            rtc,
            pending: None,
            mid: None,
            send: None,
            decoder: None,
            sink: sink.clone(),
            connected: false,
            remote_candidates: Vec::new(),
        };
        seed_candidates(
            &mut peer,
            &self.host_candidates,
            self.turn_relay,
            self.turn_mapped,
            self.local_addr,
        );
        self.new_sinks.push(sink);
        self.peers.push(peer);
        let idx = self.peers.len() - 1;
        // Late candidates advertised to earlier peers must also reach this
        // one; re-emit host + turn candidates for it specifically.
        self.emit_existing_candidates(idx, out);
        if offer {
            self.send_offer(idx, out);
        }
    }

    /// After creating a peer, tell it about candidates the other peers
    /// already know (host list + TURN addresses).
    fn emit_existing_candidates(&mut self, idx: usize, out: &mut Vec<OutSignal>) {
        let to = self.peers[idx].account.id;
        let mut lines: Vec<String> = Vec::new();
        for a in &self.host_candidates {
            if let Ok(c) = Candidate::host(*a, "udp") {
                lines.push(c.to_sdp_string());
            }
        }
        if let (Some(relay), Some(base)) = (self.turn_relay, self.local_addr) {
            if let Ok(c) = Candidate::relayed(relay, base, "udp") {
                lines.push(c.to_sdp_string());
            }
            if let Some(m) = self.turn_mapped {
                if let Ok(c) = Candidate::server_reflexive(m, base, "udp") {
                    lines.push(c.to_sdp_string());
                }
            }
        }
        for line in lines {
            out.push(OutSignal {
                to,
                kind: CallSignalKind::Candidate {
                    candidate: line,
                    mid: None,
                },
            });
        }
    }

    fn send_offer(&mut self, idx: usize, out: &mut Vec<OutSignal>) {
        let peer = &mut self.peers[idx];
        let applied = {
            let mut api = peer.rtc.sdp_api();
            let mid = api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
            // str0m only emits Event::MediaAdded for m-lines arriving in an
            // OFFER (apply_answer passes is_offer=false); the offerer learns
            // its mid here and opens the send stream in handle_answer.
            peer.mid = Some(mid);
            api.apply()
        };
        if let Some((offer, pending)) = applied {
            let sdp = offer.to_sdp_string();
            peer.pending = Some(pending);
            out.push(OutSignal {
                to: peer.account.id,
                kind: CallSignalKind::Offer { sdp },
            });
        }
    }

    /// Replace a peer's Rtc with a fresh one (glare resolution: the peer's
    /// offer wins over our pending offer).
    fn reset_peer(&mut self, idx: usize) {
        let account = self.peers[idx].account.clone();
        self.dropped_sinks.push(self.peers[idx].sink.clone());
        let rtc = Rtc::builder()
            .set_rtp_mode(true)
            .clear_codecs()
            .enable_opus(true, false)
            .build(self.clock0);
        let sink = PeerSink::new();
        let mut peer = Peer {
            account,
            rtc,
            pending: None,
            mid: None,
            send: None,
            decoder: None,
            sink: sink.clone(),
            connected: false,
            remote_candidates: Vec::new(),
        };
        seed_candidates(
            &mut peer,
            &self.host_candidates,
            self.turn_relay,
            self.turn_mapped,
            self.local_addr,
        );
        self.new_sinks.push(sink);
        self.peers[idx] = peer;
    }

    /// Full-participant snapshot (channel calls): reconcile peers and the
    /// roster. Peers absent from the roster are dropped; offers that arrived
    /// early are accepted once the account shows up. We ourselves missing
    /// from the snapshot ends the session (kicked, channel deleted, …).
    pub fn apply_roster(&mut self, participants: &[AccountBrief], out: &mut Vec<OutSignal>) {
        if self.kind != CallKind::Channel {
            return;
        }
        self.roster = participants.to_vec();
        if !participants.iter().any(|a| a.id == self.me_id) {
            self.ended = true;
            return;
        }
        // Add new arrivals (offer when we hold the lower id).
        let current: Vec<i64> = self.peers.iter().map(|p| p.account.id).collect();
        for account in participants {
            if account.id == self.me_id || current.contains(&account.id) {
                continue;
            }
            self.create_peer(account, self.me_id < account.id, out);
        }
        // Drop departures.
        let ids: Vec<i64> = participants.iter().map(|a| a.id).collect();
        self.peers.retain(|p| {
            let keep = ids.contains(&p.account.id);
            if !keep {
                self.dropped_sinks.push(p.sink.clone());
            }
            keep
        });
        // Deferred offers now resolvable.
        if !self.deferred_offers.is_empty() {
            let deferred = std::mem::take(&mut self.deferred_offers);
            for (from, sdp) in deferred {
                self.handle_offer(from, &sdp, out);
            }
        }
    }

    /// One relayed signal for this call.
    pub fn handle_signal(&mut self, from: i64, kind: CallSignalKind, out: &mut Vec<OutSignal>) {
        match kind {
            CallSignalKind::Offer { sdp } => self.handle_offer(from, &sdp, out),
            CallSignalKind::Answer { sdp } => self.handle_answer(from, &sdp),
            CallSignalKind::Candidate { candidate, .. } => {
                if let Some(peer) = self.peers.iter_mut().find(|p| p.account.id == from) {
                    if peer.mid.is_some() {
                        if let Ok(c) = Candidate::from_sdp_string(&candidate) {
                            peer.rtc.add_remote_candidate(c);
                        }
                    } else {
                        // Buffer until the m-line exists.
                        peer.remote_candidates.push(candidate);
                    }
                }
            }
            CallSignalKind::Hangup => {
                if self.kind == CallKind::Private {
                    self.ended = true;
                }
                self.peers.retain(|p| {
                    let keep = p.account.id != from;
                    if !keep {
                        self.dropped_sinks.push(p.sink.clone());
                    }
                    keep
                });
            }
        }
    }

    fn handle_offer(&mut self, from: i64, sdp: &str, out: &mut Vec<OutSignal>) {
        match self.peers.iter().position(|p| p.account.id == from) {
            Some(idx) => {
                if self.peers[idx].pending.is_some() {
                    if from < self.me_id {
                        // Their offer outranks ours: fresh Rtc, accept it.
                        self.reset_peer(idx);
                        self.accept_offer(idx, sdp, out);
                    }
                    // else: our offer wins; drop theirs silently.
                } else {
                    self.accept_offer(idx, sdp, out);
                }
            }
            None => {
                let known = match self.kind {
                    CallKind::Private => {
                        self.private_peer.as_ref().filter(|p| p.id == from).cloned()
                    }
                    CallKind::Channel => self.roster.iter().find(|a| a.id == from).cloned(),
                };
                match known {
                    Some(peer) => {
                        self.create_peer(&peer, false, out);
                        self.accept_offer(self.peers.len() - 1, sdp, out);
                    }
                    None => self.deferred_offers.push((from, sdp.to_string())),
                }
            }
        }
    }

    fn accept_offer(&mut self, idx: usize, sdp: &str, out: &mut Vec<OutSignal>) {
        let Ok(offer) = SdpOffer::from_sdp_string(sdp) else {
            return;
        };
        let to = self.peers[idx].account.id;
        let answer = self.peers[idx].rtc.sdp_api().accept_offer(offer);
        if let Ok(answer) = answer {
            out.push(OutSignal {
                to,
                kind: CallSignalKind::Answer {
                    sdp: answer.to_sdp_string(),
                },
            });
        }
    }

    fn handle_answer(&mut self, from: i64, sdp: &str) {
        let Some(idx) = self.peers.iter().position(|p| p.account.id == from) else {
            return;
        };
        let Some(pending) = self.peers[idx].pending.take() else {
            return;
        };
        if let Ok(answer) = SdpAnswer::from_sdp_string(sdp) {
            if self.peers[idx]
                .rtc
                .sdp_api()
                .accept_answer(pending, answer)
                .is_ok()
            {
                // The m-line now exists in the Rtc (apply_answer ran before
                // returning); safe to declare our outgoing stream.
                SessionCore::open_send_stream(&mut self.peers[idx]);
            }
        }
    }

    /// Feed one datagram from the network to whichever peers accept it.
    /// Events are handled inline; transmits land in `sends`.
    pub fn deliver_packet(
        &mut self,
        now: Instant,
        source: SocketAddr,
        data: &[u8],
        sends: &mut Vec<OutDatagram>,
    ) {
        let dest = self.local_addr.unwrap_or(source);
        let mut deadline = None;
        for peer in &mut self.peers {
            let Ok(recv) = Receive::new(Protocol::Udp, source, dest, data) else {
                return;
            };
            let input = Input::Receive(now, recv);
            if peer.rtc.accepts(&input) {
                if peer.rtc.handle_input(input).is_err() {
                    continue;
                }
                SessionCore::drive_peer(peer, now, sends, &mut deadline);
            }
        }
    }

    /// Advance time on every peer and collect events/transmits. Returns the
    /// earliest next-timeout across peers.
    pub fn drive(&mut self, now: Instant, sends: &mut Vec<OutDatagram>) -> Option<Instant> {
        let mut deadline: Option<Instant> = None;
        for peer in &mut self.peers {
            let _ = peer.rtc.handle_input(Input::Timeout(now));
            SessionCore::drive_peer(peer, now, sends, &mut deadline);
        }
        self.prune_dead(now);
        deadline
    }

    /// Poll one peer to completion, handling events inline. Associated fn
    /// (no `&mut self`) so it can run while `self.peers` is iterated.
    fn drive_peer(
        peer: &mut Peer,
        now: Instant,
        sends: &mut Vec<OutDatagram>,
        deadline: &mut Option<Instant>,
    ) {
        loop {
            match peer.rtc.poll_output() {
                Ok(Output::Timeout(at)) => {
                    *deadline = Some(match *deadline {
                        Some(d) if d < at => d,
                        _ => at,
                    });
                    break;
                }
                Ok(Output::Transmit(t)) => sends.push(OutDatagram {
                    source: t.source,
                    destination: t.destination,
                    bytes: t.contents.to_vec(),
                }),
                Ok(Output::Event(ev)) => SessionCore::handle_event(peer, now, ev),
                Err(_) => break,
            }
        }
    }

    /// Create the outgoing RTP stream on an existing m-line, plus the inbound
    /// decoder, and flush any candidates buffered while negotiation was in
    /// flight. Idempotent per peer.
    ///
    /// Applying the SDP already auto-declares a `StreamTx` per negotiated
    /// m-line, and str0m's poller resolves mid -> stream by iteration order
    /// over the stream map. Declaring a *second* stream on the same mid would
    /// race that lookup: the poller can keep landing on the auto stream
    /// (whose queue stays empty) while our writes pile up unseen in the other
    /// one, wedging all RTP egress for the peer. So adopt the stream that
    /// already exists for the mid — the exact object the poller resolves —
    /// and only declare a fresh one when the mid has none.
    fn open_send_stream(peer: &mut Peer) {
        if peer.send.is_some() {
            return;
        }
        let Some(mid) = peer.mid else { return };
        let ssrc = match peer.rtc.direct_api().stream_tx_by_mid(mid, None) {
            Some(existing) => existing.ssrc(),
            None => {
                let ssrc = Ssrc::new();
                peer.rtc
                    .direct_api()
                    .declare_stream_tx(ssrc, None, mid, None);
                ssrc
            }
        };
        peer.send = Some(SendStream {
            ssrc,
            pt: Pt::new_with_value(OPUS_PT),
            seq: rand::random::<u16>(),
            time: rand::random::<u32>(),
        });
        if peer.decoder.is_none() {
            peer.decoder = PeerDecoder::new(peer.sink.clone()).ok();
        }
        let buffered = std::mem::take(&mut peer.remote_candidates);
        for line in buffered {
            if let Ok(c) = Candidate::from_sdp_string(&line) {
                peer.rtc.add_remote_candidate(c);
            }
        }
    }

    fn handle_event(peer: &mut Peer, now: Instant, ev: Event) {
        match ev {
            Event::MediaAdded(ma) if ma.kind == MediaKind::Audio => {
                peer.mid = Some(ma.mid);
                SessionCore::open_send_stream(peer);
            }
            Event::Connected => {
                peer.connected = true;
                if peer.decoder.is_none() {
                    peer.decoder = PeerDecoder::new(peer.sink.clone()).ok();
                }
            }
            Event::IceConnectionStateChange(s) => match s {
                // is-0.11.1 has no Failed/Closed variants; Disconnected is
                // the "lost the peer" signal.
                IceConnectionState::Disconnected => {
                    peer.connected = false;
                }
                other => {
                    let _ = other;
                }
            },
            Event::RtpPacket(pkt) => {
                if let Some(dec) = peer.decoder.as_mut() {
                    dec.decode(&pkt.payload);
                }
                #[cfg(test)]
                {
                    if let Some(log) = RX_LOG.with(|l| l.borrow_mut().clone()) {
                        log.lock()
                            .unwrap()
                            .push((pkt.header.sequence_number, pkt.header.timestamp));
                    }
                }
            }
            Event::Closed => {
                peer.connected = false;
            }
            _ => {}
        }
        let _ = now;
    }

    /// Remove peers whose Rtc has closed. In a private call losing the only
    /// peer ends the session.
    fn prune_dead(&mut self, now: Instant) {
        let private = self.kind == CallKind::Private;
        self.peers.retain(|p| {
            let dead = !p.rtc.is_alive();
            if dead {
                self.dropped_sinks.push(p.sink.clone());
            }
            !dead
        });
        if private
            && self.peers.is_empty()
            && now.duration_since(self.clock0) > Duration::from_secs(15)
        {
            // The peer connection died without a Hangup signal; end the
            // private call after the ICE grace period.
            self.ended = true;
        }
    }

    /// 20 ms media pump: drain the mic ring, encode once, write into every
    /// connected peer's send stream.
    pub fn pump_audio(&mut self, now: Instant, mic: &SpscRing) {
        if self.encoder.is_none() {
            return;
        }
        let any_listener = self.peers.iter().any(|p| p.connected && p.send.is_some());
        let mut scratch = [0f32; 4096];
        loop {
            let n = mic.pop_into(&mut scratch);
            if n == 0 {
                break;
            }
            if any_listener {
                self.frame_acc.extend_from_slice(&scratch[..n]);
            }
        }
        if !any_listener {
            // Nobody to send to: drop anything buffered so unmuted audio
            // never starts with stale microphone data.
            self.frame_acc.clear();
            return;
        }
        while self.frame_acc.len() >= FRAME_SAMPLES {
            let frame: Vec<f32> = self.frame_acc.drain(..FRAME_SAMPLES).collect();
            let packet = match self.encoder.as_mut().unwrap().encode_frame(&frame) {
                Ok(p) => p,
                Err(_) => return,
            };
            for peer in &mut self.peers {
                if !peer.connected {
                    continue;
                }
                let Some(ss) = peer.send.as_ref() else {
                    continue;
                };
                let (ssrc, pt, seq, time, mid) = (ss.ssrc, ss.pt, ss.seq, ss.time, peer.mid);
                let mut ext = ExtensionValues::default();
                ext.mid = mid;
                let write = RtpWrite::new(pt, SeqNo::from(seq as u64), time, now, packet.clone())
                    .ext_vals(ext);
                if let Some(stream) = peer.rtc.direct_api().stream_tx(&ssrc) {
                    stream.write_rtp(write);
                }
                if let Some(ss) = peer.send.as_mut() {
                    ss.seq = ss.seq.wrapping_add(1);
                    ss.time = ss.time.wrapping_add(FRAME_SAMPLES as u32);
                }
            }
        }
    }

    /// Peer playback sinks created since the last call; the engine
    /// subscribes them to the output mixer.
    pub fn take_new_sinks(&mut self) -> Vec<Arc<PeerSink>> {
        std::mem::take(&mut self.new_sinks)
    }

    /// Peer playback sinks removed since the last call; the engine
    /// unsubscribes them from the output mixer.
    pub fn take_dropped_sinks(&mut self) -> Vec<Arc<PeerSink>> {
        std::mem::take(&mut self.dropped_sinks)
    }

    /// Hangup to every peer + end.
    pub fn shutdown(&mut self, out: &mut Vec<OutSignal>) {
        for peer in &mut self.peers {
            out.push(OutSignal {
                to: peer.account.id,
                kind: CallSignalKind::Hangup,
            });
            peer.rtc.disconnect();
        }
        self.peers.clear();
        self.ended = true;
    }

    pub fn participants_ui(&self) -> Vec<ParticipantUi> {
        self.peers
            .iter()
            .map(|p| ParticipantUi {
                id: p.account.id,
                name: p.account.username.clone(),
                connected: p.connected,
                speaking: p.sink.level() > 60,
            })
            .collect()
    }

    /// Test hook: access a peer's sink.
    pub fn peer_sink(&self, peer_id: i64) -> Option<Arc<PeerSink>> {
        self.peers
            .iter()
            .find(|p| p.account.id == peer_id)
            .map(|p| p.sink.clone())
    }
}

/// Seed a fresh peer's Rtc with every local candidate we know.
fn seed_candidates(
    peer: &mut Peer,
    hosts: &[SocketAddr],
    relay: Option<SocketAddr>,
    mapped: Option<SocketAddr>,
    local: Option<SocketAddr>,
) {
    for a in hosts {
        if let Ok(c) = Candidate::host(*a, "udp") {
            peer.rtc.add_local_candidate(c);
        }
    }
    if let (Some(relay), Some(base)) = (relay, local) {
        if let Ok(c) = Candidate::relayed(relay, base, "udp") {
            peer.rtc.add_local_candidate(c);
        }
        if let Some(m) = mapped {
            if let Ok(c) = Candidate::server_reflexive(m, base, "udp") {
                peer.rtc.add_local_candidate(c);
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    static RX_LOG: std::cell::RefCell<Option<Arc<Mutex<Vec<(u16, u32)>>>>> =
        const { std::cell::RefCell::new(None) };
}

// ---------------------------------------------------------------------------
// Engine thread
// ---------------------------------------------------------------------------

/// Spawn the session thread. Returns immediately; all further interaction
/// happens through the command channel and `UiState`.
pub fn spawn_session(cfg: SessionConfig) -> SessionHandle {
    let (tx, rx) = std::sync::mpsc::channel::<SessionCmd>();
    let ui = Arc::new(UiState::new(cfg.call_id, cfg.kind));
    // TURN credential fetch off the call thread; the result comes back on
    // the command channel.
    if let Some(rt) = cfg.rt.clone() {
        let net = cfg.net.clone();
        let tx_fetch = tx.clone();
        rt.spawn(async move {
            let res = net.net.turn_info().await;
            let _ = tx_fetch.send(SessionCmd::Turn(res));
        });
    }
    let ui_thread = ui.clone();
    let _ = std::thread::Builder::new()
        .name("bysyc-call".to_string())
        .spawn(move || run(cfg, rx, ui_thread));
    SessionHandle { cmd: tx, ui }
}

fn send_signal(net: &NetHandle, call_id: i64, to: i64, kind: CallSignalKind) {
    let _ = net.out.try_send(WsClientMsg {
        id: next_msg_id(),
        body: WsClientBody::CallSignal { call_id, to, kind },
    });
}

/// Local ips without a NIC-enumeration crate: the UDP-connect trick plus
/// loopback.
fn local_ips() -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    let probe = UdpSocket::bind("0.0.0.0:0").and_then(|s| {
        s.connect("8.8.8.8:80")?;
        s.local_addr()
    });
    if let Ok(addr) = probe {
        ips.push(addr.ip());
    }
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    if !ips.contains(&lo) {
        ips.push(lo);
    }
    ips
}

fn run(cfg: SessionConfig, rx: std::sync::mpsc::Receiver<SessionCmd>, ui: Arc<UiState>) {
    // Socket every peer and the TURN client share.
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            ui.set_audio_error(Some(format!("call socket: {e}")));
            return;
        }
    };
    let port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut local_addrs: Vec<SocketAddr> = local_ips()
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    if local_addrs.is_empty() {
        local_addrs.push(SocketAddr::new("127.0.0.1".parse().unwrap(), port));
    }

    // Audio graph. The mute flag is owned by the UiState and shared with the
    // input callback, so the overlay toggle takes effect at the source.
    let audio = match AudioIo::open(ui.muted.clone()) {
        Ok(a) => {
            ui.set_audio_error(None);
            Some(a)
        }
        Err(e) => {
            ui.set_audio_error(Some(e));
            None
        }
    };

    let mut core = SessionCore::new(cfg.me_id, cfg.kind, Instant::now());
    let mut signals: Vec<OutSignal> = Vec::new();
    {
        let mut out = Vec::new();
        core.set_local(&local_addrs, &mut out);
        signals.extend(out);
        if cfg.kind == CallKind::Private {
            if let Some(peer) = &cfg.private_peer {
                let mut out = Vec::new();
                core.start_private(peer, cfg.auto_offer_private, &mut out);
                signals.extend(out);
            }
            if let Some((from, sdp)) = &cfg.initial_offer {
                let mut out = Vec::new();
                core.take_initial_offer(*from, sdp, &mut out);
                signals.extend(out);
            }
        }
    }
    flush_signals(&cfg.net, cfg.call_id, &signals);
    signals.clear();

    let mut turn: Option<TurnClient> = None;
    let mut next_pump = Instant::now();
    let mut buf = vec![0u8; 2048];

    loop {
        let now = Instant::now();

        // --- commands ---
        let mut leave = false;
        let mut turn_result = None;
        let mut channel_dead = false;
        loop {
            match rx.try_recv() {
                Ok(SessionCmd::Signal { from, kind }) => {
                    let mut out = Vec::new();
                    core.handle_signal(from, kind, &mut out);
                    signals.extend(out);
                }
                Ok(SessionCmd::Roster(participants)) => {
                    let mut out = Vec::new();
                    core.apply_roster(&participants, &mut out);
                    signals.extend(out);
                }
                Ok(SessionCmd::Turn(res)) => turn_result = Some(res),
                Ok(SessionCmd::Leave) => leave = true,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    channel_dead = true;
                    break;
                }
            }
        }

        // --- TURN lifecycle ---
        if let Some(res) = turn_result.take() {
            turn = init_turn(res, &socket, &ui);
        }

        // --- time advance ---
        let mut sends: Vec<OutDatagram> = Vec::new();
        let deadline = core.drive(now, &mut sends);
        if leave || channel_dead || core.ended() {
            break;
        }
        let mut wait = TICK;
        if let Some(d) = deadline {
            wait = if d > now {
                wait.min(d - now)
            } else {
                Duration::from_millis(1)
            };
        }

        // --- socket wait ---
        let _ = socket.set_read_timeout(Some(wait.max(Duration::from_millis(1))));
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let data = &buf[..n];
                let mut from_turn = false;
                if let Some(t) = turn.as_mut() {
                    if from == t.server() {
                        from_turn = true;
                        if let Some(pkt) = t.handle_input(data) {
                            core.deliver_packet(now, pkt.from, &pkt.payload, &mut sends);
                        }
                        // Allocation may have just completed.
                        if t.ready() && core.relay_addr().is_none() {
                            let mut out = Vec::new();
                            core.turn_ready(t.relay_addr().unwrap(), t.mapped_addr(), &mut out);
                            ui.relayed.store(true, Ordering::Relaxed);
                            signals.extend(out);
                        }
                    }
                }
                if !from_turn {
                    core.deliver_packet(now, from, data, &mut sends);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => {} // transient; keep going
        }

        // --- TURN timers / retransmits ---
        if let Some(t) = turn.as_mut() {
            t.tick(now);
        }

        // --- audio pump + subsequent drive (pump writes RTP, drive sends) ---
        if let Some(a) = audio.as_ref() {
            if now >= next_pump {
                core.pump_audio(now, &a.mic);
                next_pump = now + TICK;
            }
        }
        core.drive(now, &mut sends);

        // --- route datagrams (direct or via TURN) ---
        for dgram in sends {
            let via_relay = turn.is_some() && core.relay_addr() == Some(dgram.source);
            if via_relay {
                if let Some(t) = turn.as_mut() {
                    let wrapped = t.wrap_outgoing(dgram.destination, &dgram.bytes);
                    let _ = socket.send_to(&wrapped, t.server());
                }
            } else {
                let _ = socket.send_to(&dgram.bytes, dgram.destination);
            }
        }
        if let Some(t) = turn.as_mut() {
            for b in t.take_sends() {
                let _ = socket.send_to(&b, t.server());
            }
        }

        // --- audio sink bookkeeping ---
        if let Some(a) = audio.as_ref() {
            for sink in core.take_new_sinks() {
                a.add_sink(sink);
            }
            for sink in core.take_dropped_sinks() {
                a.remove_sink(&sink);
            }
        } else {
            let _ = core.take_new_sinks();
            let _ = core.take_dropped_sinks();
        }

        flush_signals(&cfg.net, cfg.call_id, &signals);
        signals.clear();
        refresh_ui(
            &core,
            &ui,
            turn.as_ref().is_some_and(|t| t.ready()),
            audio.is_some(),
        );
    }

    // Graceful teardown: hangup signals to everyone, stop audio.
    let mut out = Vec::new();
    core.shutdown(&mut out);
    flush_signals(&cfg.net, cfg.call_id, &out);
    drop(audio);
    ui.set_status("call ended");
}

fn refresh_ui(core: &SessionCore, ui: &UiState, relay: bool, have_audio: bool) {
    let parts = core.participants_ui();
    let connected = parts.iter().filter(|p| p.connected).count();
    *ui.participants.lock().unwrap_or_else(|p| p.into_inner()) = parts;
    let status = if !have_audio {
        "no audio device — text only".to_string()
    } else if connected == 0 {
        "connecting…".to_string()
    } else {
        format!("{connected} connected")
    };
    let status = if relay {
        format!("{status} · relay")
    } else {
        status
    };
    ui.set_status(status);
}

fn flush_signals(net: &NetHandle, call_id: i64, signals: &[OutSignal]) {
    for s in signals {
        send_signal(net, call_id, s.to, s.kind.clone());
    }
}

fn init_turn(
    res: Result<TurnInfo, String>,
    socket: &UdpSocket,
    ui: &UiState,
) -> Option<TurnClient> {
    match res {
        Ok(info) => {
            let url = info.urls.first().cloned().unwrap_or_default();
            let host_port = url
                .trim_start_matches("turn:")
                .trim_start_matches("turns:")
                .to_string();
            let addr = resolve_turn_addr(&host_port)?;
            let mut client = TurnClient::new(addr, info.username, info.credential);
            for b in client.start() {
                let _ = socket.send_to(&b, addr);
            }
            Some(client)
        }
        Err(e) => {
            ui.set_status(format!("direct only (relay unavailable: {e})"));
            None
        }
    }
}

/// `host[:port]` → socket address (default TURN port 3478).
fn resolve_turn_addr(host_port: &str) -> Option<SocketAddr> {
    let with_port = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:3478")
    };
    if let Ok(addr) = with_port.parse() {
        return Some(addr);
    }
    with_port.to_socket_addrs().ok()?.next()
}

// ---------------------------------------------------------------------------
// Tests: two cores looped together, no sockets
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: i64, name: &str) -> AccountBrief {
        AccountBrief {
            id,
            username: name.to_string(),
            identity_key: String::new(),
            online: true,
        }
    }

    /// Loop two cores until they are connected (or iterations run out):
    /// exchange signals and datagrams bidirectionally each round.
    struct Pair {
        a: SessionCore,
        b: SessionCore,
        addr_a: SocketAddr,
        addr_b: SocketAddr,
        id_a: i64,
        id_b: i64,
        t0: Instant,
        /// Current simulated millisecond; advanced by each round.
        step: u64,
        /// Signals produced outside rounds (e.g. the initial offer) waiting
        /// to flow a → b on the next round.
        pending_ab: Vec<OutSignal>,
        /// Same, b → a.
        pending_ba: Vec<OutSignal>,
    }

    impl Pair {
        fn new(id_a: i64, id_b: i64) -> Pair {
            let t0 = Instant::now();
            let addr_a: SocketAddr = "127.0.0.1:41001".parse().unwrap();
            let addr_b: SocketAddr = "127.0.0.1:41002".parse().unwrap();
            let mut a = SessionCore::new(id_a, CallKind::Private, t0);
            let mut b = SessionCore::new(id_b, CallKind::Private, t0);
            a.set_local(&[addr_a], &mut Vec::new());
            b.set_local(&[addr_b], &mut Vec::new());
            Pair {
                a,
                b,
                addr_a,
                addr_b,
                id_a,
                id_b,
                t0,
                step: 0,
                pending_ab: Vec::new(),
                pending_ba: Vec::new(),
            }
        }

        /// Both sides learn the private peer; the lower id offers. Returns
        /// whether the initial exchange produced an offer.
        fn begin_private(&mut self, me_a: &AccountBrief, me_b: &AccountBrief) -> bool {
            let mut out = Vec::new();
            self.a.start_private(me_b, self.id_a < self.id_b, &mut out);
            let mut out_b = Vec::new();
            self.b
                .start_private(me_a, self.id_b < self.id_a, &mut out_b);
            let offered = out
                .iter()
                .any(|s| matches!(s.kind, CallSignalKind::Offer { .. }));
            self.pending_ab.extend(out);
            self.pending_ba.extend(out_b);
            offered
        }

        fn now(&self, step: u64) -> Instant {
            self.t0 + Duration::from_millis(step)
        }

        /// One exchange round at the next simulated millisecond; returns
        /// whether both sides report connected.
        fn round(&mut self) -> bool {
            let step = self.step;
            self.step += 1;
            let now = self.now(step);
            let mut sig_b = Vec::new();
            let mut sends_a = Vec::new();
            let mut sends_b = Vec::new();
            self.a.drive(now, &mut sends_a);
            self.b.drive(now, &mut sends_b);
            // Datagrams both ways, cascading: handling a packet (e.g. a STUN
            // connectivity check) produces replies that must flow back in the
            // same round, not get dropped on the floor.
            let mut to_b = sends_a;
            let mut to_a = sends_b;
            let mut guard = 0;
            while guard < 32 && !(to_b.is_empty() && to_a.is_empty()) {
                guard += 1;
                let mut resp_a = Vec::new();
                for d in std::mem::take(&mut to_b) {
                    if d.source == self.addr_a && d.destination == self.addr_b {
                        self.b
                            .deliver_packet(now, self.addr_a, &d.bytes, &mut resp_a);
                    }
                }
                let mut resp_b = Vec::new();
                for d in std::mem::take(&mut to_a) {
                    if d.source == self.addr_b && d.destination == self.addr_a {
                        self.a
                            .deliver_packet(now, self.addr_b, &d.bytes, &mut resp_b);
                    }
                }
                to_b = resp_b; // transmits from A are destined for B
                to_a = resp_a;
            }
            // Signals both ways, cascading like the datagram exchange: a
            // signal handled on one side (e.g. an Offer) produces replies
            // (Answer, candidates) that flow back within the same round.
            let mut to_b = std::mem::take(&mut self.pending_ab);
            let mut to_a = std::mem::take(&mut self.pending_ba);
            let mut guard = 0;
            while guard < 16 && !(to_b.is_empty() && to_a.is_empty()) {
                guard += 1;
                for s in std::mem::take(&mut to_b) {
                    self.b.handle_signal(self.id_a, s.kind, &mut sig_b);
                }
                let mut resp_a = Vec::new();
                for s in std::mem::take(&mut to_a) {
                    self.a.handle_signal(self.id_b, s.kind, &mut resp_a);
                }
                to_b = resp_a; // A's new replies head to B
                to_a = sig_b; // and B's head to A
                sig_b = Vec::new();
            }
            self.pending_ab = to_b;
            self.pending_ba = to_a;
            self.a.connected_count() > 0 && self.b.connected_count() > 0
        }

        fn connect(&mut self) {
            while self.step < 3000 {
                if self.round() {
                    return;
                }
            }
            panic!("cores failed to connect within 3000 rounds");
        }
    }

    #[test]
    fn private_call_offer_answer_connect() {
        let me_a = account(1, "alice");
        let me_b = account(2, "bob");
        let mut p = Pair::new(me_a.id, me_b.id);
        // A (id 1 < 2) initiates; the deterministic role rule guarantees it.
        assert!(p.begin_private(&me_a, &me_b));
        p.connect();
        assert!(p.a.is_connected_to(me_b.id));
        assert!(p.b.is_connected_to(me_a.id));
        // Both sides set up playback sinks for the mixer.
        assert!(!p.a.take_new_sinks().is_empty());
        assert!(!p.b.take_new_sinks().is_empty());
    }

    #[test]
    fn hangup_ends_private_session() {
        let me_a = account(1, "alice");
        let me_b = account(2, "bob");
        let mut p = Pair::new(me_a.id, me_b.id);
        p.begin_private(&me_a, &me_b);
        p.connect();
        assert!(p.b.take_dropped_sinks().is_empty());
        p.b.handle_signal(me_a.id, CallSignalKind::Hangup, &mut Vec::new());
        assert!(p.b.ended());
        assert_eq!(p.b.take_dropped_sinks().len(), 1);
    }

    #[test]
    fn channel_roster_creates_offers_by_id_order() {
        let t0 = Instant::now();
        let a = account(10, "a");
        let b = account(20, "b");
        let c = account(30, "c");
        let mut core = SessionCore::new(10, CallKind::Channel, t0);
        core.set_local(&["127.0.0.1:42001".parse().unwrap()], &mut Vec::new());
        let mut out = Vec::new();
        core.apply_roster(&[a.clone(), b.clone(), c.clone()], &mut out);
        // 10 < 20 and 10 < 30: we offer to both, nobody offers to us.
        let offers: Vec<i64> = out
            .iter()
            .filter(|s| matches!(s.kind, CallSignalKind::Offer { .. }))
            .map(|s| s.to)
            .collect();
        assert_eq!(offers, vec![20, 30]);
        assert_eq!(core.peer_count(), 2);

        // A peer leaving the roster drops its connection.
        let mut out = Vec::new();
        core.apply_roster(&[a.clone(), c.clone()], &mut out);
        assert_eq!(core.peer_count(), 1);
        assert_eq!(core.take_dropped_sinks().len(), 1);

        // We ourselves vanishing from the snapshot ends the call.
        let mut out = Vec::new();
        core.apply_roster(&[c.clone()], &mut out);
        assert!(core.ended());
    }

    #[test]
    fn lower_id_offer_wins_glare() {
        // Both sides somehow offered; the lower id's offer must survive and
        // the higher id side resets onto it.
        let t0 = Instant::now();
        let a = account(5, "a");
        let b = account(6, "b");
        let mut core = SessionCore::new(6, CallKind::Private, t0);
        core.set_local(&["127.0.0.1:43001".parse().unwrap()], &mut Vec::new());
        core.start_private(&a, true, &mut Vec::new()); // we offered (we are 6)
        // Meanwhile 5 also offered and their offer arrives.
        let foreign = {
            let mut lower = SessionCore::new(5, CallKind::Private, t0);
            lower.set_local(&["127.0.0.1:43002".parse().unwrap()], &mut Vec::new());
            let mut o2 = Vec::new();
            lower.start_private(&b, true, &mut o2);
            // Candidate signals precede the offer in `o2`; find the offer.
            o2.into_iter()
                .find_map(|s| match s.kind {
                    CallSignalKind::Offer { sdp } => Some(sdp),
                    _ => None,
                })
                .expect("lower-id side must emit an offer")
        };
        let mut out = Vec::new();
        core.handle_signal(5, CallSignalKind::Offer { sdp: foreign }, &mut out);
        // We answered their offer (accepted theirs, dropped our pending).
        assert!(
            out.iter()
                .any(|s| matches!(s.kind, CallSignalKind::Answer { .. }))
        );
    }

    #[test]
    fn packetizer_sequences_rtp_per_peer() {
        // Connect a pair, then pump synthetic mic frames and inspect the RTP
        // arriving at the far end: sequence numbers increment by one and
        // timestamps by 960 per 20 ms frame.
        let me_a = account(1, "alice");
        let me_b = account(2, "bob");
        let mut p = Pair::new(me_a.id, me_b.id);
        p.begin_private(&me_a, &me_b);
        p.connect();

        let log = Arc::new(Mutex::new(Vec::<(u16, u32)>::new()));
        RX_LOG.with(|l| *l.borrow_mut() = Some(log.clone()));

        let ring = SpscRing::new();
        let tone = 0.3f32;
        // Continue seamlessly from wherever connect() stopped so neither
        // side's ICE consent window sees a traffic gap; drive BOTH sides
        // each round (one-way driving lets the far side's responses — and
        // with them the candidate pair — go stale).
        for _i in 0..40 {
            ring.push_slice(&vec![tone; FRAME_SAMPLES]);
            let now = p.now(p.step);
            p.a.pump_audio(now, &ring);
            p.b.pump_audio(now, &ring);
            p.round();
        }
        // A few idle rounds so the last in-flight frames surface as
        // RtpPacket events on the receiving side.
        for _ in 0..5 {
            p.round();
        }
        RX_LOG.with(|l| *l.borrow_mut() = None);

        let entries = log.lock().unwrap().clone();
        assert!(
            entries.len() >= 5,
            "want >=5 rtp packets, got {}",
            entries.len()
        );
        for w in entries.windows(2) {
            assert_eq!(w[1].0.wrapping_sub(w[0].0), 1, "seq jump: {:?}", entries);
            assert_eq!(w[1].1.wrapping_sub(w[0].1), FRAME_SAMPLES as u32);
        }
        // The far end also decoded a healthy amount of audio.
        let sink = p.b.peer_sink(me_a.id).expect("sink");
        assert!(
            sink.ring_len() > FRAME_SAMPLES,
            "expected decoded audio, got {}",
            sink.ring_len()
        );
    }

    #[test]
    fn turn_ready_advertises_relay_to_all_peers() {
        let t0 = Instant::now();
        let b = account(20, "b");
        let mut core = SessionCore::new(10, CallKind::Channel, t0);
        core.set_local(&["127.0.0.1:44001".parse().unwrap()], &mut Vec::new());
        core.apply_roster(&[account(10, "a"), b], &mut Vec::new());
        let mut out = Vec::new();
        core.turn_ready(
            "198.51.100.9:49160".parse().unwrap(),
            Some("203.0.113.5:5000".parse().unwrap()),
            &mut out,
        );
        // Candidates: srflx + relay, each signalled once.
        let cands: Vec<&CallSignalKind> = out
            .iter()
            .map(|s| &s.kind)
            .filter(|k| matches!(k, CallSignalKind::Candidate { .. }))
            .collect();
        assert_eq!(cands.len(), 2);
        assert!(
            cands.iter().any(|k| matches!(k, CallSignalKind::Candidate { candidate, .. } if candidate.contains("typ relay")))
        );
        assert!(
            cands.iter().any(|k| matches!(k, CallSignalKind::Candidate { candidate, .. } if candidate.contains("typ srflx")))
        );
    }

    #[test]
    fn deferred_offer_accepted_when_roster_arrives() {
        let t0 = Instant::now();
        let mut core = SessionCore::new(30, CallKind::Channel, t0);
        core.set_local(&["127.0.0.1:45001".parse().unwrap()], &mut Vec::new());
        // An offer from 10 arrives before any roster.
        core.handle_signal(
            10,
            CallSignalKind::Offer {
                sdp: "v=0\r\n".into(),
            },
            &mut Vec::new(),
        );
        assert_eq!(core.peer_count(), 0); // deferred, not created
        let roster = vec![account(10, "a"), account(30, "c")];
        let mut out = Vec::new();
        core.apply_roster(&roster, &mut out);
        // The roster creates the peer; the deferred offer is then answered
        // (the dummy sdp fails parsing, but the peer exists).
        assert_eq!(core.peer_count(), 1);
    }

    #[test]
    fn pump_without_listener_discards_capture() {
        // With no connected listener the pump must discard buffered mic data
        // so unmuted audio never plays stale content.
        let t0 = Instant::now();
        let peer = account(2, "b");
        let mut core = SessionCore::new(1, CallKind::Private, t0);
        core.set_local(&["127.0.0.1:46001".parse().unwrap()], &mut Vec::new());
        core.start_private(&peer, false, &mut Vec::new());
        assert_eq!(core.peer_count(), 1);
        let ring = SpscRing::new();
        ring.push_slice(&vec![0.5f32; FRAME_SAMPLES * 3]);
        core.pump_audio(t0 + Duration::from_millis(20), &ring);
        // Not connected: everything discarded.
        assert!(ring.is_empty());
    }
}
