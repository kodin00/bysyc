//! Password hashing (Argon2id). Owned by S1 — this stub fixes the signatures
//! that auth (S2) and bootstrap_admin (S1) code against.

/// Hash a password with Argon2id and a fresh random salt (PHC string format).
pub fn hash_password(password: &str) -> String {
    let _ = password;
    unimplemented!("S1 implements hash_password")
}

/// Verify a password against a stored PHC string. False on any parse failure.
pub fn verify_password(password: &str, phc: &str) -> bool {
    let _ = (password, phc);
    unimplemented!("S1 implements verify_password")
}
