// src/xwing_sig_65.rs

extern crate alloc;

use super::{combiner, consts::MASTER_SEED_SIZE, Error};
use alloc::vec::Vec;
use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey, Verifier,
    VerifyingKey as EdVerifyingKey,
};
use libcrux_ml_dsa::ml_dsa_65::{
    generate_key_pair, sign as ml_dsa_sign, verify as ml_dsa_verify, MLDSA65KeyPair,
    MLDSA65Signature, MLDSA65VerificationKey,
};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{Digest, ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Shake256};
use zeroize::ZeroizeOnDrop;

const ML_PK_SIZE: usize = 1952; // Approximate size for ML-DSA-65 public key
const ED_PK_SIZE: usize = 32;

const BINDING_TAG_SIZE: usize = 32;

const ML_SIG_SIZE: usize = 3309; // Exact size for ML-DSA-65 signature
pub const VERIFYING_KEY_SIZE: usize = ML_PK_SIZE + ED_PK_SIZE;

#[derive(Clone)]
pub struct VerifyingKey {
    vk_ml: MLDSA65VerificationKey,
    vk_ed: EdVerifyingKey,
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct SigningKey {
    seed: [u8; MASTER_SEED_SIZE],
}

impl SigningKey {
    pub fn new(seed: [u8; MASTER_SEED_SIZE]) -> Self {
        Self { seed }
    }
}

#[derive(Clone)]
pub struct Signature {
    sig_ml: MLDSA65Signature,
    sig_ed: EdSignature,
    binding_tag: [u8; BINDING_TAG_SIZE],
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl VerifyingKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(VERIFYING_KEY_SIZE);
        buffer.extend_from_slice(self.vk_ml.as_ref());
        buffer.extend_from_slice(self.vk_ed.as_bytes());
        buffer
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let message_hash = Sha3_256::digest(message);
        ml_dsa_verify(&self.vk_ml, message, &[], &signature.sig_ml)
            .map_err(|_| Error::InvalidMlDsaSignature)?;
        let expected_tag = combiner(
            signature.sig_ml.as_ref(),
            signature.sig_ed.to_bytes().as_ref(),
            &message_hash,
        );
        if expected_tag != signature.binding_tag {
            return Err(Error::BindingTagMismatch);
        }
        self.vk_ed
            .verify(message, &signature.sig_ed)
            .map_err(|_| Error::InvalidEd25519Signature)?;
        Ok(())
    }
}

impl From<&[u8; VERIFYING_KEY_SIZE]> for VerifyingKey {
    fn from(bytes: &[u8; VERIFYING_KEY_SIZE]) -> Self {
        let vk_ml_bytes: [u8; ML_PK_SIZE] = bytes[..ML_PK_SIZE].try_into().unwrap();
        let vk_ml = MLDSA65VerificationKey::new(vk_ml_bytes);
        let vk_ed_bytes: [u8; ED_PK_SIZE] = bytes[ML_PK_SIZE..].try_into().unwrap();
        let vk_ed = EdVerifyingKey::from_bytes(&vk_ed_bytes).unwrap();
        Self { vk_ml, vk_ed }
    }
}

impl SigningKey {
    pub fn sign(
        &self,
        message: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Signature, Error> {
        let (kp_ml, sk_ed) = expand_seed(&self.seed);
        let sk_ml = kp_ml.signing_key;
        let mut rand = [0u8; 32];
        rng.fill_bytes(&mut rand);
        let sig_ml = ml_dsa_sign(&sk_ml, message, &[], rand).map_err(|_| Error::MlDsaSignError)?;
        let sig_ed = sk_ed.sign(message);
        let message_hash = Sha3_256::digest(message);
        let binding_tag = combiner(sig_ml.as_ref(), sig_ed.to_bytes().as_ref(), &message_hash);
        Ok(Signature {
            sig_ml,
            sig_ed,
            binding_tag,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let (kp_ml, sk_ed) = expand_seed(&self.seed);
        let vk_ml = kp_ml.verification_key;
        let vk_ed = sk_ed.verifying_key();
        VerifyingKey { vk_ml, vk_ed }
    }
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(self.sig_ml.as_ref());
        buffer.extend_from_slice(self.sig_ed.to_bytes().as_ref());
        buffer.extend_from_slice(&self.binding_tag);
        buffer
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        const TAG_SIZE: usize = 32;
        if bytes.len() != ML_SIG_SIZE + 64 + TAG_SIZE {
            return Err(Error::InvalidSignatureLength);
        }
        let sig_ml_bytes: [u8; ML_SIG_SIZE] = bytes[..ML_SIG_SIZE].try_into().unwrap();
        let sig_ml = MLDSA65Signature::new(sig_ml_bytes);
        let sig_ed_bytes: [u8; 64] = bytes[ML_SIG_SIZE..ML_SIG_SIZE + 64].try_into().unwrap();
        let sig_ed = EdSignature::from_bytes(&sig_ed_bytes);
        let binding_tag: [u8; TAG_SIZE] = bytes[ML_SIG_SIZE + 64..].try_into().unwrap();
        Ok(Signature {
            sig_ml,
            sig_ed,
            binding_tag,
        })
    }
}

pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; MASTER_SEED_SIZE];
    rng.fill_bytes(&mut seed);
    let (kp_ml, sk_ed) = expand_seed(&seed);
    let vk_ml = kp_ml.verification_key;
    let vk_ed = sk_ed.verifying_key();
    (SigningKey::new(seed), VerifyingKey { vk_ml, vk_ed })
}

fn expand_seed(seed: &[u8; MASTER_SEED_SIZE]) -> (MLDSA65KeyPair, EdSigningKey) {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut expanded = [0u8; 64];
    reader.read(&mut expanded);
    let ml_seed: [u8; 32] = expanded[..32].try_into().unwrap();
    let ed_seed: [u8; 32] = expanded[32..].try_into().unwrap();
    let kp_ml = generate_key_pair(ml_seed);
    let secret_ed = ed_seed;
    let sk_ed = EdSigningKey::from(&secret_ed);
    (kp_ml, sk_ed)
}
