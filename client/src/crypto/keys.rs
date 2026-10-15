//! Key material storage and pickle-key derivation.
//!
//! The crypto engine never touches the filesystem or the OS keychain. All
//! persistent state (pickled Olm/Megolm sessions) is written through the
//! [`KeyStore`] trait, which the app layer implements on top of its local
//! database. The passphrase that protects the pickles is likewise supplied
//! by the app layer (ADR 0001: one device per Account; key export is the
//! reinstall/recovery story).

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;

/// Persistent byte-blob store the [`crate::crypto::Engine`] pickles into.
///
/// The contract with the store crate (`client/src/store.rs`): one blob per
/// `scope` string, last write wins, `get` returns the most recent `put`.
///
/// Implementations must be usable from multiple threads: the engine holds an
/// `Arc<dyn KeyStore>` and calls through `&self`, so the trait requires
/// `Send + Sync` (a `Mutex`-wrapped handle trivially satisfies both).
pub trait KeyStore: Send + Sync {
    /// Fetch the blob stored under `scope`, if any.
    fn get(&self, scope: &str) -> Option<Vec<u8>>;
    /// Store `blob` under `scope`, replacing any previous value.
    fn put(&self, scope: &str, blob: &[u8]);
    /// Remove the blob under `scope`, if present.
    fn delete(&self, scope: &str);
}

/// Trivial in-memory [`KeyStore`], used by the engine's unit tests and handy
/// as a reference implementation for the real store. Wrap it in an `Arc` to
/// share one between engines. Compiled only under `cfg(test)`: production
/// code always persists through the app layer's real store.
#[cfg(test)]
#[derive(Default)]
pub struct MemKeyStore(Mutex<HashMap<String, Vec<u8>>>);

#[cfg(test)]
impl KeyStore for MemKeyStore {
    fn get(&self, scope: &str) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(scope).cloned()
    }

    fn put(&self, scope: &str, blob: &[u8]) {
        self.0.lock().unwrap().insert(scope.into(), blob.to_vec());
    }

    fn delete(&self, scope: &str) {
        self.0.lock().unwrap().remove(scope);
    }
}

/// Scope under which the pickled Olm [`vodozemac::olm::Account`] lives.
pub(crate) const SCOPE_OLM_ACCOUNT: &str = "olm_account";
/// Scope holding the serialized table of pickled Olm peer sessions.
pub(crate) const SCOPE_OLM_SESSIONS: &str = "olm_sessions";
/// Scope holding the serialized table of pickled outbound Megolm sessions.
pub(crate) const SCOPE_MEGOLM_OUT: &str = "megolm_out";
/// Scope holding the serialized table of pickled inbound Megolm sessions.
pub(crate) const SCOPE_MEGOLM_IN: &str = "megolm_in";
/// Scope holding queued [`crate::crypto::PendingShare`]s not yet mailed out.
pub(crate) const SCOPE_PENDING_SHARES: &str = "pending_shares";

/// Salt for deriving the key that encrypts pickles inside the local store.
pub(crate) const STORE_SALT: &[u8] = b"bysyc.store.v1";
/// Salt for deriving the key that encrypts an exported identity backup.
pub(crate) const EXPORT_SALT: &[u8] = b"bysyc.export.v1";

/// Derive the 32-byte pickle-encryption key from a passphrase.
///
/// vodozemac encrypts every pickle with a `[u8; 32]` key; the app hands us a
/// passphrase instead. There is no KDF crate in the dependency set yet
/// (`sha2`/`argon2` should be added — see the engine report), so this uses a
/// self-contained, fully specified SHA-256 (below) in a salted iterated
/// construction. In production the passphrase is a high-entropy random secret
/// from the OS keychain, for which this is more than adequate; a human-chosen
/// passphrase (identity export) would benefit from a memory-hard KDF later.
pub(crate) fn derive_pickle_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let pass = passphrase.as_bytes();
    // 1024 rounds of acc = H(salt || acc || passphrase). Each round re-folds
    // the full passphrase and the domain salt, so no round output is
    // derivable without the passphrase.
    let mut acc = sha256(salt);
    for _ in 0..1024 {
        let mut buf = Vec::with_capacity(salt.len() + 32 + pass.len());
        buf.extend_from_slice(salt);
        buf.extend_from_slice(&acc);
        buf.extend_from_slice(pass);
        acc = sha256(&buf);
    }
    acc
}

/// SHA-256, FIPS 180-4, self-contained so the crate needs no `sha2` dep.
/// Validated against `shasum -a 256` vectors in the tests below.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Message padding: data || 0x80 || zeros || 64-bit big-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// All vectors generated with `shasum -a 256`; the 56-byte and 1000-byte
    /// inputs force multi-block padding paths.
    #[test]
    fn sha256_matches_shasum_vectors() {
        let cases: &[(&str, &str)] = &[
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                "bysyc",
                "36baa3f781a698cd122cf82b1eb6c3427f5ada80cb193021805505e8ea3a4f1d",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(&hex(&sha256(input.as_bytes())), want, "input: {input:?}");
        }
        // 1000 x 'a' — exercises many blocks and a length that spans blocks.
        let thousand_a = vec![b'a'; 1000];
        assert_eq!(
            hex(&sha256(&thousand_a)),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn derive_pickle_key_is_deterministic_and_salt_sensitive() {
        let a = derive_pickle_key("correct horse battery staple", STORE_SALT);
        let b = derive_pickle_key("correct horse battery staple", STORE_SALT);
        let c = derive_pickle_key("correct horse battery staplz", STORE_SALT);
        let d = derive_pickle_key("correct horse battery staple", EXPORT_SALT);
        assert_eq!(a, b, "same passphrase + salt must give same key");
        assert_ne!(a, c, "different passphrase must give different key");
        assert_ne!(a, d, "different salt must give different key");
    }

    #[test]
    fn mem_key_store_roundtrip() {
        let store = MemKeyStore::default();
        assert_eq!(store.get("scope"), None);
        store.put("scope", b"value");
        assert_eq!(store.get("scope"), Some(b"value".to_vec()));
        store.put("scope", b"value2");
        assert_eq!(store.get("scope"), Some(b"value2".to_vec()));
        store.delete("scope");
        assert_eq!(store.get("scope"), None);
        store.delete("scope"); // deleting a missing scope is a no-op
    }
}
