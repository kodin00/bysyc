//! Immediate-mode views rendered per frame from [`crate::state`].
//!
//! - [`login`]: instance URL + login/register, shown while not logged in.
//! - [`main_view`]: the three-column app (nav / channels-or-friends / chat).
//! - [`attachments`]: E2EE file send/receive in the chat view (C4).
//! - [`emoji`]: monochrome emoji font + the composer's emoji picker.

pub mod attachments;
pub mod emoji;
pub mod login;
pub mod main_view;
