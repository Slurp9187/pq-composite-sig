use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Sha3_256};
use xwing_sig::*;

fn rng() -> ChaCha12Rng {
    ChaCha12Rng::from_seed([0u8; 32])
}

#[cfg(test)]
mod combiner_tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    #[test]
    fn test_combiner_consistency() {
        let sig_ml = b"mock_ml_sig";
        let sig_ed = ed25519_dalek::Signature::from_bytes(&[1u8; 64]);
        let message_hash = Sha3_256::digest(b"message");

        let result1 = combiner::combiner(sig_ml, sig_ed.to_bytes().as_ref(), &message_hash);
        let result2 = combiner::combiner(sig_ml, sig_ed.to_bytes().as_ref(), &message_hash);

        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_combiner_different_inputs() {
        let sig_ml1 = b"mock_ml_sig1";
        let sig_ml2 = b"mock_ml_sig2";
        let sig_ed = ed25519_dalek::Signature::from_bytes(&[1u8; 64]);
        let message_hash = Sha3_256::digest(b"message");

        let result1 = combiner::combiner(sig_ml1, sig_ed.to_bytes().as_ref(), &message_hash);
        let result2 = combiner::combiner(sig_ml2, sig_ed.to_bytes().as_ref(), &message_hash);

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_combiner_includes_label() {
        let sig_ml = b"mock_ml_sig";
        let sig_ed = ed25519_dalek::Signature::from_bytes(&[1u8; 64]);
        let message_hash = Sha3_256::digest(b"message");

        let combined = combiner::combiner(sig_ml, sig_ed.to_bytes().as_ref(), &message_hash);

        // Plain hash without label
        let plain_hash = Sha3_256::new()
            .chain_update(sig_ml)
            .chain_update(sig_ed.to_bytes().as_ref())
            .chain_update(&message_hash)
            .finalize();

        assert_ne!(combined, plain_hash.as_slice());
    }

    #[test]
    fn test_combiner_all_zero_inputs() {
        let sig_ml = [0u8; 10];
        let sig_ed = [0u8; 64];
        let message_hash = [0u8; 32];

        let result = combiner::combiner(&sig_ml, &sig_ed, &message_hash);
        // Should still produce a non-zero hash due to the label
        assert!(!result.iter().all(|&b| b == 0));
        assert_eq!(result.len(), 32);
    }
}

// Tests for xwing_sig_65 (default)
#[test]
fn test_generate_keypair_65() {
    use xwing_sig::xwing_sig_65::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    assert_eq!(sk.verifying_key().to_bytes(), pk.to_bytes());
}

#[test]
fn test_sign_verify_roundtrip_65() {
    use xwing_sig::xwing_sig_65::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(message, &sig).is_ok());
}

#[test]
fn test_verify_invalid_message_65() {
    use xwing_sig::xwing_sig_65::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let wrong_message = b"Goodbye, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(wrong_message, &sig).is_err());
}

#[test]
fn test_verify_tampered_signature_65() {
    use xwing_sig::xwing_sig_65::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    let mut sig_bytes = sig.to_bytes();
    let ed_start = 3309; // ML_SIG_SIZE for 65
    sig_bytes[ed_start + 1] ^= 1; // Flip a bit in Ed sig
    let tampered_sig = XwingSig65Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_verify_binding_tag_mismatch_65() {
    use xwing_sig::xwing_sig_65::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    let mut sig_bytes = sig.to_bytes();
    let tag_start = 3309 + 64; // ML_SIG_SIZE + ED_SIG_SIZE for 65
    sig_bytes[tag_start] ^= 1; // Flip a bit in binding tag
    let tampered_sig = XwingSig65Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_serialization_roundtrip_65() {
    use xwing_sig::xwing_sig_65::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();

    let pk_bytes = pk.to_bytes();
    let sig_bytes = sig.to_bytes();

    let pk_deserialized = XwingSig65VerifyingKey::from(&pk_bytes[..VERIFYING_KEY_SIZE].try_into().unwrap());
    let sig_deserialized = XwingSig65Signature::try_from(&sig_bytes[..]).unwrap();

    assert_eq!(pk.to_bytes(), pk_deserialized.to_bytes());
    assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes());
    assert!(pk_deserialized.verify(message, &sig_deserialized).is_ok());
}

#[test]
fn test_deterministic_keys_from_seed_65() {
    use xwing_sig::xwing_sig_65::*;
    let seed1 = [1u8; 32];
    let seed2 = [1u8; 32];
    let pk1 = XwingSig65SigningKey::new(seed1).verifying_key();
    let pk2 = XwingSig65SigningKey::new(seed2).verifying_key();
    assert!(pk1 == pk2, "Verifying keys should be equal");
}

#[test]
fn test_verify_wrong_key_65() {
    use xwing_sig::xwing_sig_65::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let (_wrong_sk, wrong_pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(message, &sig).is_ok());
    assert!(wrong_pk.verify(message, &sig).is_err());
}

// Tests for xwing_sig_44
#[test]
fn test_generate_keypair_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_44(&mut rng);
    assert_eq!(sk.verifying_key().to_bytes(), pk.to_bytes());
}

#[test]
fn test_sign_verify_roundtrip_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_44(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(message, &sig).is_ok());
}

#[test]
fn test_verify_invalid_message_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_44(&mut rng);
    let message = b"Hello, world!";
    let wrong_message = b"Goodbye, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(wrong_message, &sig).is_err());
}

#[test]
fn test_verify_tampered_signature_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_44(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    let mut sig_bytes = sig.to_bytes();
    let ed_start = 2420; // ML_SIG_SIZE for 44
    sig_bytes[ed_start + 1] ^= 1; // Flip a bit in Ed sig
    let tampered_sig = XwingSig44Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_verify_binding_tag_mismatch_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_44(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    let mut sig_bytes = sig.to_bytes();
    let tag_start = 2420 + 64; // ML_SIG_SIZE + ED_SIG_SIZE for 44
    sig_bytes[tag_start] ^= 1; // Flip a bit in binding tag
    let tampered_sig = XwingSig44Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_serialization_roundtrip_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_44(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();

    let pk_bytes = pk.to_bytes();
    let sig_bytes = sig.to_bytes();

    let pk_deserialized =
        XwingSig44VerifyingKey::from(&pk_bytes[..VERIFYING_KEY_SIZE].try_into().unwrap());
    let sig_deserialized = XwingSig44Signature::try_from(&sig_bytes[..]).unwrap();

    assert_eq!(pk.to_bytes(), pk_deserialized.to_bytes());
    assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes());
    assert!(pk_deserialized.verify(message, &sig_deserialized).is_ok());
}

#[test]
fn test_deterministic_keys_from_seed_44() {
    use xwing_sig::xwing_sig_44::*;
    let seed1 = [1u8; 32];
    let seed2 = [1u8; 32];
    let pk1 = XwingSig44SigningKey::new(seed1).verifying_key();
    let pk2 = XwingSig44SigningKey::new(seed2).verifying_key();
    assert!(pk1 == pk2, "Verifying keys should be equal");
}

#[test]
fn test_verify_wrong_key_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_44(&mut rng);
    let (_wrong_sk, wrong_pk) = generate_keypair_xwing_sig_44(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(message, &sig).is_ok());
    assert!(wrong_pk.verify(message, &sig).is_err());
}

// Tests for xwing_sig_87
#[test]
fn test_generate_keypair_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    assert_eq!(sk.verifying_key().to_bytes(), pk.to_bytes());
}

#[test]
fn test_sign_verify_roundtrip_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(message, &sig).is_ok());
}

#[test]
fn test_verify_invalid_message_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let wrong_message = b"Goodbye, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(wrong_message, &sig).is_err());
}

#[test]
fn test_verify_tampered_signature_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    let mut sig_bytes = sig.to_bytes();
    let ed_start = 4627; // ML_SIG_SIZE for 87
    sig_bytes[ed_start + 1] ^= 1; // Flip a bit in Ed sig
    let tampered_sig = XwingSig87Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_verify_binding_tag_mismatch_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    let mut sig_bytes = sig.to_bytes();
    let tag_start = 4627 + 64; // ML_SIG_SIZE + ED_SIG_SIZE for 87
    sig_bytes[tag_start] ^= 1; // Flip a bit in binding tag
    let tampered_sig = XwingSig87Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_serialization_roundtrip_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();

    let pk_bytes = pk.to_bytes();
    let sig_bytes = sig.to_bytes();

    let pk_deserialized =
        XwingSig87VerifyingKey::from(&pk_bytes[..VERIFYING_KEY_SIZE].try_into().unwrap());
    let sig_deserialized = XwingSig87Signature::try_from(&sig_bytes[..]).unwrap();

    assert_eq!(pk.to_bytes(), pk_deserialized.to_bytes());
    assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes());
    assert!(pk_deserialized.verify(message, &sig_deserialized).is_ok());
}

#[test]
fn test_deterministic_keys_from_seed_87() {
    use xwing_sig::xwing_sig_87::*;
    let seed1 = [1u8; 32];
    let seed2 = [1u8; 32];
    let pk1 = XwingSig87SigningKey::new(seed1).verifying_key();
    let pk2 = XwingSig87SigningKey::new(seed2).verifying_key();
    assert!(pk1 == pk2, "Verifying keys should be equal");
}

#[test]
fn test_verify_wrong_key_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair_xwing_sig_65(&mut rng);
    let (_wrong_sk, wrong_pk) = generate_keypair_xwing_sig_65(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng).unwrap();
    assert!(pk.verify(message, &sig).is_ok());
    assert!(wrong_pk.verify(message, &sig).is_err());
}

#[test]
fn test_combiner_function() {
    let sig_ml = b"mock_ml_sig";
    let sig_ed = ed25519_dalek::Signature::from_bytes(&[0u8; 64]);
    let message_hash = Sha3_256::digest(b"message");
    let result = combiner::combiner(sig_ml, sig_ed.to_bytes().as_ref(), &message_hash);
    // Compute expected tag manually
    let mut hasher = Sha3_256::new();
    hasher.update(sig_ml);
    hasher.update(sig_ed.to_bytes().as_ref());
    hasher.update(&message_hash);
    hasher.update(b"X-WING-SIG");
    let expected = hasher.finalize();
    assert_eq!(result, expected.as_slice());
}
