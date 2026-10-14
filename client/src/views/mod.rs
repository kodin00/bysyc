//! Immediate-mode views rendered per frame from [`crate::state`].
//!
//! - [`login`]: instance URL + login/register, shown while not logged in.
//! - [`main_view`]: the three-column app (nav / channels-or-friends / chat).

pub mod login;
pub mod main_view;
