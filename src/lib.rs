// src/lib.rs

//! # xwing_sig
//!
//! X-Wing hybrid post-quantum signature (ML-DSA-44/65/87 + Ed25519)
//! using libcrux-ml-dsa and rustcrypto/ed25519.
//!
//! Implements a draft hybrid signature protocol.
//!
//! Currently provides:
//! - `xwing_sig_87`: ML-DSA-87 + Ed25519 variant
//! - `xwing_sig_65`: ML-DSA-65 + Ed25519 variant (default for balanced security/performance)
//! - `xwing_sig_44`: ML-DSA-44 + Ed25519 variant

// #![no_std]
// #![deny(missing_docs)]
// #![deny(unsafe_code)]

extern crate alloc;

pub mod aliases;
pub mod combiner;
pub mod consts;
pub mod error;
pub mod xwing_sig_44;
pub mod xwing_sig_65;
pub mod xwing_sig_87;

pub use combiner::combiner;
pub use xwing_sig_65::*;

pub const XWING_SIG_VERSION: &str = "01";

pub use consts::{MASTER_SEED_SIZE, SHARED_LABEL};
