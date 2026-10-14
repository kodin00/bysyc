//! The plaintext payload format carried inside every encrypted blob.
//!
//! All content the app exchanges — chat text, file descriptors, Megolm
//! session shares, delete notices — is serialized to one of these
//! [`Envelope`] variants as JSON before encryption:
//!
//! - [`Envelope::Chat`], [`Envelope::File`], [`Envelope::Delete`] ride the
//!   *Megolm* channel sessions (guild text channels; see ADR 0001).
//! - [`Envelope::SessionShare`] rides the *pairwise Olm* sessions through
//!   the directed mailbox (the WhatsApp sender-key bootstrap).
//!
//! The enum follows the wire conventions of `bysyc_common::protocol`:
//! snake_case fields, externally tagged variants, so a serialized
//! [`Envelope::Chat`] looks like
//! `{"chat":{"text":"hi","reply_to":null}}`.

use serde::{Deserialize, Serialize};

/// The plaintext inside a Message or mailbox ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Envelope {
    /// Human-visible text Message.
    Chat {
        /// Message body.
        text: String,
        /// Id of the Message this replies to, if any.
        reply_to: Option<i64>,
    },
    /// A file attachment, uploaded encrypted out-of-band.
    File {
        /// Original file name chosen by the sender.
        name: String,
        /// Ciphertext size in bytes.
        size: i64,
        /// Base64 AES-GCM nonce of the attachment (see [`crate::crypto::Engine::encrypt_file`]).
        nonce: String,
        /// Base64 AES-256-GCM content key; only readable inside this envelope.
        key: String,
        /// Server-assigned attachment id the ciphertext was stored under.
        attachment_id: i64,
    },
    /// A Megolm `session_key` hand-off to one peer over Olm (mailbox).
    SessionShare {
        /// Channel the Megolm session encrypts.
        channel_id: i64,
        /// Id of the shared Megolm session. Megolm messages do not carry
        /// their session id, so receivers need it alongside the key.
        session_id: String,
        /// Base64 `SessionKey` exported from the sender's outbound session.
        session_key: String,
    },
    /// Sender asks peers to locally delete a Message they can see.
    Delete {
        /// Id of the target Message.
        target: i64,
    },
}

impl Envelope {
    /// Serialize to the compact JSON string that gets encrypted.
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse the JSON string produced by [`Envelope::to_json`].
    pub fn from_json(json: &str) -> anyhow::Result<Envelope> {
        Ok(serde_json::from_str(json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_roundtrip() {
        let variants = vec![
            Envelope::Chat {
                text: "hello".into(),
                reply_to: None,
            },
            Envelope::Chat {
                text: "hello again".into(),
                reply_to: Some(42),
            },
            Envelope::File {
                name: "cat.png".into(),
                size: 4096,
                nonce: "bm9uY2U=".into(),
                key: "a2V5".into(),
                attachment_id: 300,
            },
            Envelope::SessionShare {
                channel_id: 7,
                session_id: "cWVjaW9uSWQ".into(),
                session_key: "c2Vzc2lvbktleQ".into(),
            },
            Envelope::Delete { target: 123 },
        ];
        for v in variants {
            let json = v.to_json().unwrap();
            assert_eq!(Envelope::from_json(&json).unwrap(), v, "json: {json}");
        }
    }

    #[test]
    fn wire_shape_is_externally_tagged_snake_case() {
        let json = Envelope::Chat {
            text: "hi".into(),
            reply_to: None,
        }
        .to_json()
        .unwrap();
        assert_eq!(json, r#"{"chat":{"text":"hi","reply_to":null}}"#);

        let json = Envelope::Delete { target: 9 }.to_json().unwrap();
        assert_eq!(json, r#"{"delete":{"target":9}}"#);
    }
}
