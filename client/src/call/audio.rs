//! Call audio path — cpal capture/playback, Opus codec, mixing.
//!
//! Layout (one dedicated call thread owns everything except the cpal
//! callbacks):
//!
//! * **Capture**: the cpal input callback downmixes to mono and resamples to
//!   48 kHz (naive linear interpolation — fine for speech) into a shared
//!   [`SpscRing`], entirely through preallocated scratch — once warmed up
//!   neither cpal callback locks or allocates. The session thread drains the
//!   ring, cuts 20 ms (960-sample) frames and Opus-encodes each frame once
//!   for all peers. Mute stops the capture push at the source (the encoder
//!   is simply not fed).
//! * **Playback**: every peer owns a [`PeerSink`] (an SPSC ring the session
//!   thread fills with decoded frames). The session thread publishes the
//!   peer list as an immutable snapshot (`arc-swap`); the cpal output
//!   callback takes one lock-free snapshot load, bulk-pops every started
//!   sink into per-peer scratch and mixes with saturation.
//!
//! The rings are single-producer/single-consumer with Acquire/Release
//! indices — the weakest obviously-correct ordering for SPSC (the producer
//! publishes samples with a Release tail store, the consumer publishes
//! reads with a Release head store). Per-peer prebuffering (32 ms) keeps a
//! new stream from crackling before it has jitter margin; overflow drops
//! the oldest samples to bound latency.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

/// Samples per 20 ms frame at 48 kHz (Opus voip frame size).
pub const FRAME_SAMPLES: usize = 960;
/// Ring capacity per direction: 400 ms at 48 kHz (power of two).
const RING_SAMPLES: usize = 1 << 15; // 32768
/// Samples buffered before a peer starts playing (jitter margin).
const PREBUFFER_SAMPLES: usize = 1536; // 32 ms
/// Session sample rate; Opus requires 48 kHz.
pub const SAMPLE_RATE: u32 = 48_000;

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

/// Wait-free SPSC ring of f32 samples.
///
/// Producer: `push_slice`; consumer: `pop_into`. On overflow the oldest
/// samples are dropped (latency stays bounded); on underflow the consumer
/// simply receives fewer samples.
pub struct SpscRing {
    buf: UnsafeCell<Box<[f32]>>,
    mask: usize,
    head: AtomicU64, // consumer position (samples ever read)
    tail: AtomicU64, // producer position (samples ever written)
    overflowed: AtomicU64,
    underflowed: AtomicU64,
}

// Safety: the buffer is only ever touched through positions guarded by the
// Release/Acquire head/tail atomics (producer writes below tail, consumer
// reads below head), the classic SPSC arrangement.
unsafe impl Sync for SpscRing {}

impl SpscRing {
    pub fn new() -> Self {
        assert!(RING_SAMPLES.is_power_of_two());
        SpscRing {
            buf: UnsafeCell::new(vec![0.0; RING_SAMPLES].into_boxed_slice()),
            mask: RING_SAMPLES - 1,
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
            underflowed: AtomicU64::new(0),
        }
    }

    pub fn len(&self) -> usize {
        let t = self.tail.load(Ordering::Acquire);
        let h = self.head.load(Ordering::Relaxed);
        (t - h) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Samples dropped because the ring was full.
    pub fn overflow_count(&self) -> u64 {
        self.overflowed.load(Ordering::Relaxed)
    }

    /// Reads that asked for more than was buffered.
    pub fn underflow_count(&self) -> u64 {
        self.underflowed.load(Ordering::Relaxed)
    }

    /// Producer side: append `samples`, dropping the oldest on overflow.
    pub fn push_slice(&self, samples: &[f32]) {
        let mut tail = self.tail.load(Ordering::Relaxed); // producer-owned
        let head = self.head.load(Ordering::Acquire);
        let used = (tail - head) as usize;
        if samples.len() + used > RING_SAMPLES {
            let drop_n = samples.len() + used - RING_SAMPLES;
            self.head.store(head + drop_n as u64, Ordering::Release);
            self.overflowed.fetch_add(drop_n as u64, Ordering::Relaxed);
        }
        // Safety: producer-only region; consumer reads only below `head`.
        let buf = unsafe { &mut *self.buf.get() };
        for &s in samples {
            buf[(tail & self.mask as u64) as usize] = s;
            tail += 1;
        }
        self.tail.store(tail, Ordering::Release); // publish the new samples
    }

    /// Consumer side: pop up to `out.len()` samples, returning how many
    /// were filled. The remainder is left untouched.
    pub fn pop_into(&self, out: &mut [f32]) -> usize {
        let head = self.head.load(Ordering::Relaxed); // consumer-owned
        let tail = self.tail.load(Ordering::Acquire);
        let avail = (tail - head) as usize;
        let n = avail.min(out.len());
        if n < out.len() {
            self.underflowed
                .fetch_add((out.len() - n) as u64, Ordering::Relaxed);
        }
        // Safety: consumer-only region; producer writes only above `tail`.
        let buf = unsafe { &*self.buf.get() };
        let mut head = head;
        for slot in out.iter_mut().take(n) {
            *slot = buf[(head & self.mask as u64) as usize];
            head += 1;
        }
        // Publish the read position only after the copies are done.
        self.head.store(head, Ordering::Release);
        n
    }

    /// Drop everything; used when a peer leaves so stale audio cannot play.
    pub fn clear(&self) {
        let tail = self.tail.load(Ordering::Acquire);
        self.head.store(tail, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Playback sink (one per remote peer)
// ---------------------------------------------------------------------------

/// Per-peer playback state shared between the session thread (producer) and
/// the output callback (consumer).
pub struct PeerSink {
    ring: SpscRing,
    started: AtomicBool,
    /// Recent input RMS * 200, 0-255; the UI reads it as "speaking".
    level: AtomicU8,
}

impl PeerSink {
    pub fn new() -> Arc<PeerSink> {
        Arc::new(PeerSink {
            ring: SpscRing::new(),
            started: AtomicBool::new(false),
            level: AtomicU8::new(0),
        })
    }

    pub fn push_samples(&self, samples: &[f32]) {
        let rms = (samples.iter().map(|s| s * s).sum::<f32>() / samples.len().max(1) as f32).sqrt();
        let l = (rms.clamp(0.0, 1.0) * 255.0) as u8;
        self.level.store(l, Ordering::Relaxed);
        self.ring.push_slice(samples);
    }

    pub fn level(&self) -> u8 {
        self.level.load(Ordering::Relaxed)
    }

    /// Samples currently buffered for playback (diagnostics + tests).
    pub fn ring_len(&self) -> usize {
        self.ring.len()
    }

    fn reset(&self) {
        self.started.store(false, Ordering::SeqCst);
        self.level.store(0, Ordering::Relaxed);
        self.ring.clear();
    }
}

// ---------------------------------------------------------------------------
// Resampler + channel downmix (capture path, runs in the input callback)
// ---------------------------------------------------------------------------

/// Streaming linear resampler: arbitrary source rate → 48 kHz mono, keeping
/// the fractional read position across calls.
#[derive(Default)]
pub struct LinearResampler {
    /// Last sample of the previous chunk (mono).
    last: f32,
    /// Fractional position within the virtual source stream since `last`.
    frac: f32,
}

impl LinearResampler {
    /// `input` is mono at `from_rate`. Resampled 48 kHz samples are appended
    /// to `out` (caller-owned scratch, so nothing allocates once warm) and
    /// the slice to push is returned. On passthrough (`from_rate` is already
    /// 48 kHz) the input is borrowed directly — no copy at all.
    pub fn process_into<'a>(
        &mut self,
        input: &'a [f32],
        from_rate: u32,
        out: &'a mut Vec<f32>,
    ) -> &'a [f32] {
        if input.is_empty() {
            return input;
        }
        if from_rate == SAMPLE_RATE {
            self.last = *input.last().unwrap();
            return input;
        }
        let step = from_rate as f32 / SAMPLE_RATE as f32;
        out.clear();
        out.reserve((input.len() as f32 / step).ceil() as usize + 1);
        let mut pos = self.frac; // position (in samples) relative to input[0]
        while pos < input.len() as f32 {
            let i = pos.floor() as usize;
            let a = if i == 0 { self.last } else { input[i - 1] };
            let b = input[i.min(input.len() - 1)];
            let t = pos - i as f32;
            out.push(a + (b - a) * t);
            pos += step;
        }
        self.frac = pos - input.len() as f32;
        self.last = *input.last().unwrap();
        out
    }
}

/// Average interleaved channels down to mono, appending to `out` (caller
/// scratch; capacity is reused across calls so the input callback never
/// allocates once warm).
pub fn downmix_into(input: &[f32], channels: usize, out: &mut Vec<f32>) {
    if channels <= 1 {
        out.extend_from_slice(input);
        return;
    }
    out.reserve(input.len() / channels);
    for c in input.chunks(channels) {
        out.push(c.iter().sum::<f32>() / channels as f32);
    }
}

// ---------------------------------------------------------------------------
// Opus wrappers
// ---------------------------------------------------------------------------

/// One shared encoder for the microphone (20 ms mono voip frames). Sequence
/// numbers / RTP timestamps belong to each peer's send stream, not the
/// encoder, so every peer transmits the same encoded bytes under its own
/// SSRC/seq/clock.
pub struct MicEncoder {
    enc: opus::Encoder,
    /// Reused max-packet-size (1275 B) output scratch; Opus overwrites
    /// `[..n]`, only the right-sized packet is copied out.
    buf: Vec<u8>,
    /// Bytes of the last encoded frame (for tests/statistics).
    pub last_len: usize,
}

impl MicEncoder {
    pub fn new() -> Result<Self, opus::Error> {
        let mut enc =
            opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)?;
        let _ = enc.set_bitrate(opus::Bitrate::Bits(24_000));
        let _ = enc.set_inband_fec(true);
        let _ = enc.set_packet_loss_perc(15);
        Ok(MicEncoder {
            enc,
            buf: vec![0u8; 1275], // max Opus packet size, allocated once
            last_len: 0,
        })
    }

    /// Encode one 960-sample frame into Opus bytes.
    pub fn encode_frame(&mut self, frame: &[f32]) -> Result<Vec<u8>, opus::Error> {
        let n = self.enc.encode_float(frame, &mut self.buf)?;
        self.last_len = n;
        Ok(self.buf[..n].to_vec())
    }

    /// Encode into a caller-owned buffer — zero steady-state allocation on
    /// the send path; the caller reuses one Vec across frames.
    pub fn encode_frame_into(
        &mut self,
        frame: &[f32],
        out: &mut Vec<u8>,
    ) -> Result<usize, opus::Error> {
        let n = self.enc.encode_float(frame, &mut self.buf)?;
        self.last_len = n;
        out.clear();
        out.extend_from_slice(&self.buf[..n]);
        Ok(n)
    }
}

/// Per-peer decoder feeding a [`PeerSink`].
pub struct PeerDecoder {
    dec: opus::Decoder,
    sink: Arc<PeerSink>,
    /// Reused decode scratch (60 ms headroom), allocated once. Opus fills
    /// `[..n]`; stale samples beyond `n` are never read, so it is never
    /// re-zeroed.
    pcm: Vec<f32>,
}

impl PeerDecoder {
    pub fn new(sink: Arc<PeerSink>) -> Result<Self, opus::Error> {
        Ok(PeerDecoder {
            dec: opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono)?,
            sink,
            pcm: vec![0f32; FRAME_SAMPLES * 3], // headroom for 60 ms frames
        })
    }

    pub fn sink(&self) -> Arc<PeerSink> {
        self.sink.clone()
    }

    /// Decode one RTP payload into the sink. An empty payload runs packet
    /// loss concealment (PLC), which we also use on visible jitter gaps.
    pub fn decode(&mut self, payload: &[u8]) {
        match self.dec.decode_float(payload, &mut self.pcm, false) {
            Ok(n) => self.sink.push_samples(&self.pcm[..n]),
            Err(_) => {
                // Corrupt packet: conceal one frame rather than glitch.
                if let Ok(n) = self.dec.decode_float(&[], &mut self.pcm, false) {
                    self.sink.push_samples(&self.pcm[..n]);
                }
            }
        }
    }

    /// Fill one concealment frame (used when nothing arrived this pump).
    pub fn conceal(&mut self) {
        if let Ok(n) = self.dec.decode_float(&[], &mut self.pcm, false) {
            self.sink.push_samples(&self.pcm[..n]);
        }
    }
}

// ---------------------------------------------------------------------------
// cpal engine
// ---------------------------------------------------------------------------

/// Open capture + playback and return the shared handles.
///
/// Streams start paused in cpal 0.18 and are played here; dropping the
/// returned `AudioIo` stops both. Device/format failures are surfaced as
/// human-readable strings for the overlay status line.
pub struct AudioIo {
    /// Mono 48 kHz microphone samples (empty while muted).
    pub mic: Arc<SpscRing>,
    /// Registered peer sinks behind a lock-free snapshot: the session
    /// thread publishes a fresh immutable list on membership change, the
    /// output callback takes a single `load_full`. (`ArcSwap<Vec<..>>`
    /// rather than `Arc<[..]>` — arc-swap cannot hold unsized pointees.)
    pub sinks: Arc<ArcSwap<Vec<Arc<PeerSink>>>>,
    pub mute: Arc<AtomicBool>,
    /// Device description for status text.
    pub device_note: String,
    _input: cpal::Stream,
    _output: cpal::Stream,
}

impl AudioIo {
    pub fn open(mute: Arc<AtomicBool>) -> Result<AudioIo, String> {
        let host = cpal::default_host();
        let in_dev = host.default_input_device().ok_or("no microphone device")?;
        let out_dev = host.default_output_device().ok_or("no speaker device")?;

        // ---- input: prefer f32 @ 48 kHz, fall back to any f32 range ----
        let in_cfg = in_dev
            .supported_input_configs()
            .map_err(|e| format!("microphone config: {e}"))?
            .filter(|r| r.sample_format() == cpal::SampleFormat::F32)
            .find_map(|r| r.try_with_sample_rate(SAMPLE_RATE))
            .or_else(|| {
                in_dev
                    .supported_input_configs()
                    .ok()?
                    .filter(|r| r.sample_format() == cpal::SampleFormat::F32)
                    .next()
                    .map(|r| r.with_max_sample_rate())
            })
            .ok_or("no f32 microphone format")?;
        let in_rate = in_cfg.sample_rate(); // SampleRate is a plain u32 alias
        let in_channels = in_cfg.channels() as usize;
        let in_config = cpal::StreamConfig {
            channels: in_cfg.channels(),
            sample_rate: in_cfg.sample_rate(),
            buffer_size: cpal::BufferSize::Default,
        };

        let mic = Arc::new(SpscRing::new());
        let mic_in = mic.clone();
        let mute_in = mute.clone();
        let mut resampler = LinearResampler::default();
        let mut mono_scratch: Vec<f32> = Vec::new();
        let mut resampled_scratch: Vec<f32> = Vec::new();
        let input = in_dev
            .build_input_stream(
                in_config,
                move |data: &[f32], _info: &cpal::InputCallbackInfo| {
                    if mute_in.load(Ordering::Relaxed) {
                        return; // muted: capture nothing at the source
                    }
                    // Everything runs through closure-owned scratch: after
                    // the first few callbacks this path neither locks nor
                    // allocates.
                    mono_scratch.clear();
                    downmix_into(data, in_channels, &mut mono_scratch);
                    let to_push =
                        resampler.process_into(&mono_scratch, in_rate, &mut resampled_scratch);
                    mic_in.push_slice(to_push);
                },
                |err| {
                    // Device errors surface through the ring's health; a
                    // single glitch is survivable, keep the stream alive.
                    let _ = err;
                },
                None,
            )
            .map_err(|e| format!("open microphone: {e}"))?;

        // ---- output: f32, any channel count, resampled on the fly ----
        let out_cfg = out_dev
            .supported_output_configs()
            .map_err(|e| format!("speaker config: {e}"))?
            .filter(|r| r.sample_format() == cpal::SampleFormat::F32)
            .find_map(|r| r.try_with_sample_rate(SAMPLE_RATE))
            .or_else(|| {
                out_dev
                    .supported_output_configs()
                    .ok()?
                    .filter(|r| r.sample_format() == cpal::SampleFormat::F32)
                    .next()
                    .map(|r| r.with_max_sample_rate())
            })
            .ok_or("no f32 speaker format")?;
        let out_config = cpal::StreamConfig {
            channels: out_cfg.channels(),
            sample_rate: out_cfg.sample_rate(),
            buffer_size: cpal::BufferSize::Default,
        };
        let out_channels = out_config.channels as usize;
        let out_rate = out_config.sample_rate; // captured before the move below
        let sinks = Arc::new(ArcSwap::from_pointee(Vec::<Arc<PeerSink>>::new()));
        let sinks_out = sinks.clone();
        let mut mix_scratch: Vec<f32> = Vec::new();
        let mut peer_scratch: Vec<Vec<f32>> = Vec::new();
        let output = out_dev
            .build_output_stream(
                out_config,
                move |data: &mut [f32], _info: &cpal::OutputCallbackInfo| {
                    // One lock-free snapshot load; membership changes on the
                    // session thread publish a fresh immutable list.
                    let peers = sinks_out.load_full();
                    let frames = data.len() / out_channels;
                    // Grow-only scratch: nothing allocates here once the
                    // peer count and device buffer size have settled.
                    if peer_scratch.len() < peers.len() {
                        peer_scratch.resize(peers.len(), Vec::new());
                    }
                    mix_scratch.clear();
                    mix_scratch.resize(frames, 0.0);
                    for (i, peer) in peers.iter().enumerate() {
                        if !peer.started.load(Ordering::Relaxed)
                            && peer.ring.len() >= PREBUFFER_SAMPLES
                        {
                            peer.started.store(true, Ordering::Relaxed);
                        }
                        if !peer.started.load(Ordering::Relaxed) {
                            continue;
                        }
                        let scratch = &mut peer_scratch[i];
                        if scratch.len() != frames {
                            scratch.clear();
                            scratch.resize(frames, 0.0);
                        }
                        // Bulk-pop this peer's frames once, then mix from
                        // the local buffer — two ring atomics per peer per
                        // callback instead of two per sample.
                        let n = peer.ring.pop_into(scratch);
                        for (slot, s) in mix_scratch.iter_mut().zip(scratch.iter()).take(n) {
                            *slot += *s;
                        }
                    }
                    for (frame, s) in data.chunks_exact_mut(out_channels).zip(mix_scratch.iter()) {
                        let s = s.clamp(-1.0, 1.0);
                        for ch in frame.iter_mut() {
                            *ch = s;
                        }
                    }
                },
                |err| {
                    let _ = err;
                },
                None,
            )
            .map_err(|e| format!("open speaker: {e}"))?;

        input.play().map_err(|e| format!("start microphone: {e}"))?;
        output.play().map_err(|e| format!("start speaker: {e}"))?;

        Ok(AudioIo {
            mic,
            sinks,
            mute,
            device_note: format!(
                "mic {} Hz {}ch / out {} Hz {}ch",
                in_rate, in_channels, out_rate, out_channels
            ),
            _input: input,
            _output: output,
        })
    }

    /// Session thread only: publish a new snapshot with the sink appended.
    pub fn add_sink(&self, sink: Arc<PeerSink>) {
        let cur = self.sinks.load_full();
        let mut next = Vec::with_capacity(cur.len() + 1);
        next.extend(cur.iter().cloned());
        next.push(sink);
        self.sinks.store(Arc::new(next));
    }

    /// Session thread only: publish a new snapshot without the sink.
    pub fn remove_sink(&self, sink: &Arc<PeerSink>) {
        sink.reset();
        let cur = self.sinks.load_full();
        let next: Vec<Arc<PeerSink>> = cur
            .iter()
            .filter(|s| !Arc::ptr_eq(s, sink))
            .cloned()
            .collect();
        self.sinks.store(Arc::new(next));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_fifo_and_boundaries() {
        let r = SpscRing::new();
        r.push_slice(&[1.0, 2.0, 3.0]);
        let mut out = [0f32; 2];
        assert_eq!(r.pop_into(&mut out), 2);
        assert_eq!(out, [1.0, 2.0]);
        let mut rest = [0f32; 4];
        let n = r.pop_into(&mut rest);
        assert_eq!(n, 1);
        assert_eq!(rest[0], 3.0);
        assert_eq!(r.underflow_count(), 3); // asked 4, got 1
    }

    #[test]
    fn ring_overflow_drops_oldest() {
        let r = SpscRing::new();
        let chunk = vec![0.5f32; RING_SAMPLES / 2];
        r.push_slice(&chunk);
        r.push_slice(&chunk); // full
        r.push_slice(&[9.0; 8]); // must drop 8 oldest
        assert_eq!(r.len(), RING_SAMPLES);
        assert_eq!(r.overflow_count(), 8);
        let mut out = vec![0f32; RING_SAMPLES];
        assert_eq!(r.pop_into(&mut out), RING_SAMPLES);
        // The oldest 8 samples (0.5) were dropped; everything is 0.5 until
        // the final 8 samples (9.0).
        assert!(out[..RING_SAMPLES - 8].iter().all(|s| *s == 0.5));
        assert!(out[RING_SAMPLES - 8..].iter().all(|s| *s == 9.0));
    }

    #[test]
    fn ring_clear_resets() {
        let r = SpscRing::new();
        r.push_slice(&[1.0, 2.0]);
        r.clear();
        assert!(r.is_empty());
        let mut out = [0f32; 2];
        assert_eq!(r.pop_into(&mut out), 0);
    }

    #[test]
    fn spsc_ring_threaded_ping_pong() {
        // One producer thread, one consumer thread, arbitrary chunk sizes:
        // every sample must arrive in order exactly once.
        let ring = Arc::new(SpscRing::new());
        let total = 100_000usize;
        let producer = {
            let ring = ring.clone();
            std::thread::spawn(move || {
                let mut next = 0u32;
                while next < total as u32 {
                    // Never write past `total` on the final chunk.
                    let n = std::cmp::min(next % 97 + 1, total as u32 - next) as usize;
                    let chunk: Vec<f32> = (next..next + n as u32).map(|v| v as f32).collect();
                    // push_slice drops the OLDEST samples on overflow; for a
                    // lossless order check, wait until the chunk fits.
                    while ring.len() + chunk.len() > RING_SAMPLES {
                        std::thread::yield_now();
                    }
                    ring.push_slice(&chunk);
                    next += n as u32;
                }
            })
        };
        let consumer = {
            let ring = ring.clone();
            std::thread::spawn(move || {
                let mut expect = 0u32;
                let mut buf = [0f32; 53];
                while expect < total as u32 {
                    let n = ring.pop_into(&mut buf);
                    for s in buf.iter().take(n) {
                        assert_eq!(*s, expect as f32, "out of order at {expect}");
                        expect += 1;
                    }
                    if n == 0 {
                        std::thread::yield_now();
                    }
                }
            })
        };
        producer.join().unwrap();
        consumer.join().unwrap();
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn downmix_averages_channels() {
        let mut mono = Vec::new();
        downmix_into(&[1.0, 3.0, 2.0, 4.0], 2, &mut mono);
        assert_eq!(mono, vec![2.0, 3.0]);
        mono.clear();
        downmix_into(&[1.0, 2.0], 1, &mut mono);
        assert_eq!(mono, vec![1.0, 2.0]);
    }

    #[test]
    fn resampler_preserves_sample_count_at_same_rate() {
        let mut r = LinearResampler::default();
        let mut out = Vec::new();
        // Passthrough must borrow the input untouched (no copy).
        let res = r.process_into(&[0.1, 0.2, 0.3], SAMPLE_RATE, &mut out);
        assert_eq!(res, &[0.1, 0.2, 0.3]);
        assert!(out.is_empty());
    }

    #[test]
    fn resampler_preserves_tone_frequency() {
        // 440 Hz sine at 44.1 kHz → 48 kHz: count zero crossings over a
        // fixed duration and compare (tolerance ~1%).
        let from = 44_100u32;
        let secs = 2.0f32;
        let n = (from as f32 * secs) as usize;
        let input: Vec<f32> = (0..n)
            .map(|i| (2.0 * std::f32::consts::PI * 440.0 * i as f32 / from as f32).sin())
            .collect();
        let mut r = LinearResampler::default();
        let mut out = Vec::new();
        r.process_into(&input, from, &mut out);
        let crossings = out
            .windows(2)
            .filter(|w| (w[0] < 0.0) != (w[1] < 0.0))
            .count() as f32;
        let hz = crossings / 2.0 / (out.len() as f32 / SAMPLE_RATE as f32);
        assert!(
            (hz - 440.0).abs() < 8.0,
            "resampled tone drifted: {hz:.1} Hz"
        );
        // Length ratio is ~48/44.1.
        let ratio = out.len() as f32 / input.len() as f32;
        assert!((ratio - 48_000.0 / 44_100.0).abs() < 0.02, "ratio {ratio}");
    }

    #[test]
    fn opus_roundtrip_preserves_energy() {
        // Sine at 48 kHz, encode/decode a few frames, compare RMS energy
        // (Opus is lossy; require the envelope, not the samples).
        let mut enc = MicEncoder::new().expect("encoder");
        let sink = PeerSink::new();
        let mut dec = PeerDecoder::new(sink.clone()).expect("decoder");
        let hz = 185.0f32;
        let phase_step = 2.0 * std::f32::consts::PI * hz / SAMPLE_RATE as f32;
        let mut phase = 0f32;
        let mut rms_in = 0f32;
        let mut frames = 0f32;
        for _ in 0..25 {
            let frame: Vec<f32> = (0..FRAME_SAMPLES)
                .map(|_| {
                    let v = 0.5 * phase.sin();
                    phase += phase_step;
                    v
                })
                .collect();
            rms_in += frame.iter().map(|s| s * s).sum::<f32>();
            frames += FRAME_SAMPLES as f32;
            let packet = enc.encode_frame(&frame).expect("encode");
            dec.decode(&packet);
        }
        // Drain the sink.
        let mut got = Vec::new();
        let mut buf = [0f32; FRAME_SAMPLES];
        loop {
            let n = sink.ring.pop_into(&mut buf);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert!(got.len() > FRAME_SAMPLES * 20, "decoded {}", got.len());
        let skip = FRAME_SAMPLES; // drop the first warm-up frame
        let rms_out: f32 =
            got[skip..].iter().map(|s| s * s).sum::<f32>() / (got.len() - skip) as f32;
        let rms_in = (rms_in / frames).sqrt();
        let rms_out = rms_out.sqrt();
        assert!(
            (rms_out - rms_in).abs() / rms_in < 0.35,
            "energy drifted: in {rms_in:.3} out {rms_out:.3}"
        );
    }

    #[test]
    fn opus_plc_produces_silence_ish_output() {
        let sink = PeerSink::new();
        let mut dec = PeerDecoder::new(sink.clone()).expect("decoder");
        dec.conceal();
        dec.conceal();
        assert!(sink.ring.len() > 0);
    }

    #[test]
    fn mic_encoder_encodes_distinct_frames() {
        let mut enc = MicEncoder::new().expect("encoder");
        let frame = vec![0.05f32; FRAME_SAMPLES];
        let p0 = enc.encode_frame(&frame).unwrap();
        let p1 = enc.encode_frame(&frame).unwrap();
        assert!(!p0.is_empty() && !p1.is_empty());
        assert!(enc.last_len > 0);
    }
}
