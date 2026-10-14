//! Password hashing (Argon2id). Owned by S1 — auth (S2) and
//! `bootstrap_admin` code against these signatures.
//!
//! Both functions use `Argon2::default()`: Argon2id, version 0x13, and the
//! crate's default params (m = 19 MiB, t = 2, p = 1 — the OWASP-recommended
//! baseline for Argon2id). `verify_password` honors the params embedded in
//! the stored PHC string, so hashes minted with other settings still verify.

use argon2::{Argon2, PasswordHasher, PasswordVerifier};

/// Hash a password with Argon2id and a fresh random salt (PHC string format).
///
/// The 16-byte salt is drawn from the OS CSPRNG by the `password-hash`
/// layer (argon2's default `getrandom` feature); no external RNG wiring is
/// needed. The returned string looks like
/// `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.
pub fn hash_password(password: &str) -> String {
    // Infallible for any realistic password: the defaults accept arbitrary
    // lengths up to Argon2's 4 KiB limit and hashing cannot fail otherwise.
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("argon2: hash failed (password too long or OS RNG failure)")
        .to_string()
}

/// Verify a password against a stored PHC string. False on any parse failure
/// or mismatch; never panics.
pub fn verify_password(password: &str, phc: &str) -> bool {
    // `PasswordVerifier<str>` parses the PHC string first: a malformed,
    // truncated, or foreign-algorithm string is an `Err`, flattened here to
    // `false`. The final digest comparison is constant-time.
    Argon2::default()
        .verify_password(password.as_bytes(), phc)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verifies_roundtrip() {
        let phc = hash_password("correct horse battery staple");
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &phc));
    }

    #[test]
    fn wrong_password_fails() {
        let phc = hash_password("hunter42");
        assert!(!verify_password("hunter43", &phc));
    }

    #[test]
    fn garbage_hash_string_is_false_not_panic() {
        assert!(!verify_password("pw", ""));
        assert!(!verify_password("pw", "not-a-phc-string"));
        assert!(!verify_password(
            "pw",
            "$argon2id$v=19$m=19456,t=2,p=1$ truncated"
        ));
    }

    #[test]
    fn salts_are_fresh() {
        assert_ne!(hash_password("same"), hash_password("same"));
    }
}
