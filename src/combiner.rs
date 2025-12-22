// src/crypto/xwing_sig/combiner.rs

use sha3::{Digest, Sha3_256};

/// Combines the ML-DSA signature, Ed25519 signature, and message hash into a single binding tag using SHA3-256.
/// This follows the X-Wing signature protocol to derive a hybrid binding tag.
/// Inputs: ML-DSA signature (sig_ml), Ed25519 signature (sig_ed), SHA3-256 hash of the message (message_hash).
/// The domain separator label "X-WING-SIG" is appended to ensure uniqueness and prevent cross-protocol attacks.
pub fn combiner(sig_ml: &[u8], sig_ed: &[u8], message_hash: &[u8]) -> [u8; 32] {
    Sha3_256::new()
        .chain_update(sig_ml)
        .chain_update(sig_ed)
        .chain_update(message_hash)
        .chain_update(super::SHARED_LABEL)
        .finalize()
        .into()
}
