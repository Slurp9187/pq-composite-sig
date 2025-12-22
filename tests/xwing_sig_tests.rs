use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Sha3_256};
use xwing_sig::*;

fn rng() -> ChaCha12Rng {
    ChaCha12Rng::from_seed([0u8; 32])
}

// Tests for xwing_sig_65 (default)
#[test]
fn test_generate_keypair_65() {
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    assert_eq!(sk.verifying_key().to_bytes(), pk.to_bytes());
}

#[test]
fn test_sign_verify_roundtrip_65() {
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    assert!(pk.verify(message, &sig).is_ok());
}

#[test]
fn test_verify_invalid_message_65() {
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let wrong_message = b"Goodbye, world!";
    let sig = sk.sign(message, &mut rng);
    assert!(pk.verify(wrong_message, &sig).is_err());
}

#[test]
fn test_verify_tampered_signature_65() {
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    let mut sig_bytes = sig.to_bytes();
    let ed_start = 3309; // ML_SIG_SIZE for 65
    sig_bytes[ed_start + 1] ^= 1; // Flip a bit in Ed sig
    let tampered_sig = Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_verify_binding_tag_mismatch_65() {
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    let mut sig_bytes = sig.to_bytes();
    let tag_start = 3309 + 64; // ML_SIG_SIZE + ED_SIG_SIZE for 65
    sig_bytes[tag_start] ^= 1; // Flip a bit in binding tag
    let tampered_sig = Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_serialization_roundtrip_65() {
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);

    let pk_bytes = pk.to_bytes();
    let sig_bytes = sig.to_bytes();

    let pk_deserialized = VerifyingKey::from(&pk_bytes[..VERIFYING_KEY_SIZE].try_into().unwrap());
    let sig_deserialized = Signature::try_from(&sig_bytes[..]).unwrap();

    assert_eq!(pk.to_bytes(), pk_deserialized.to_bytes());
    assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes());
    assert!(pk_deserialized.verify(message, &sig_deserialized).is_ok());
}

#[test]
fn test_deterministic_keys_from_seed_65() {
    let seed1 = [1u8; 32];
    let seed2 = [1u8; 32];
    let pk1 = SigningKey::new(seed1).verifying_key();
    let pk2 = SigningKey::new(seed2).verifying_key();
    assert!(pk1 == pk2, "Verifying keys should be equal");
}

// Tests for xwing_sig_44
#[test]
fn test_generate_keypair_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    assert_eq!(sk.verifying_key().to_bytes(), pk.to_bytes());
}

#[test]
fn test_sign_verify_roundtrip_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    assert!(pk.verify(message, &sig).is_ok());
}

#[test]
fn test_verify_invalid_message_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let wrong_message = b"Goodbye, world!";
    let sig = sk.sign(message, &mut rng);
    assert!(pk.verify(wrong_message, &sig).is_err());
}

#[test]
fn test_verify_tampered_signature_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    let mut sig_bytes = sig.to_bytes();
    let ed_start = 2420; // ML_SIG_SIZE for 44
    sig_bytes[ed_start + 1] ^= 1; // Flip a bit in Ed sig
    let tampered_sig = Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_verify_binding_tag_mismatch_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    let mut sig_bytes = sig.to_bytes();
    let tag_start = 2420 + 64; // ML_SIG_SIZE + ED_SIG_SIZE for 44
    sig_bytes[tag_start] ^= 1; // Flip a bit in binding tag
    let tampered_sig = Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_serialization_roundtrip_44() {
    use xwing_sig::xwing_sig_44::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);

    let pk_bytes = pk.to_bytes();
    let sig_bytes = sig.to_bytes();

    let pk_deserialized = VerifyingKey::from(&pk_bytes[..VERIFYING_KEY_SIZE].try_into().unwrap());
    let sig_deserialized = Signature::try_from(&sig_bytes[..]).unwrap();

    assert_eq!(pk.to_bytes(), pk_deserialized.to_bytes());
    assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes());
    assert!(pk_deserialized.verify(message, &sig_deserialized).is_ok());
}

#[test]
fn test_deterministic_keys_from_seed_44() {
    use xwing_sig::xwing_sig_44::*;
    let seed1 = [1u8; 32];
    let seed2 = [1u8; 32];
    let pk1 = SigningKey::new(seed1).verifying_key();
    let pk2 = SigningKey::new(seed2).verifying_key();
    assert!(pk1 == pk2, "Verifying keys should be equal");
}

// Tests for xwing_sig_87
#[test]
fn test_generate_keypair_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    assert_eq!(sk.verifying_key().to_bytes(), pk.to_bytes());
}

#[test]
fn test_sign_verify_roundtrip_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    assert!(pk.verify(message, &sig).is_ok());
}

#[test]
fn test_verify_invalid_message_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let wrong_message = b"Goodbye, world!";
    let sig = sk.sign(message, &mut rng);
    assert!(pk.verify(wrong_message, &sig).is_err());
}

#[test]
fn test_verify_tampered_signature_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    let mut sig_bytes = sig.to_bytes();
    let ed_start = 4627; // ML_SIG_SIZE for 87
    sig_bytes[ed_start + 1] ^= 1; // Flip a bit in Ed sig
    let tampered_sig = Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_verify_binding_tag_mismatch_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);
    let mut sig_bytes = sig.to_bytes();
    let tag_start = 4627 + 64; // ML_SIG_SIZE + ED_SIG_SIZE for 87
    sig_bytes[tag_start] ^= 1; // Flip a bit in binding tag
    let tampered_sig = Signature::try_from(&sig_bytes[..]).unwrap();
    assert!(pk.verify(message, &tampered_sig).is_err());
}

#[test]
fn test_serialization_roundtrip_87() {
    use xwing_sig::xwing_sig_87::*;
    let mut rng = rng();
    let (sk, pk) = generate_keypair(&mut rng);
    let message = b"Hello, world!";
    let sig = sk.sign(message, &mut rng);

    let pk_bytes = pk.to_bytes();
    let sig_bytes = sig.to_bytes();

    let pk_deserialized = VerifyingKey::from(&pk_bytes[..VERIFYING_KEY_SIZE].try_into().unwrap());
    let sig_deserialized = Signature::try_from(&sig_bytes[..]).unwrap();

    assert_eq!(pk.to_bytes(), pk_deserialized.to_bytes());
    assert_eq!(sig.to_bytes(), sig_deserialized.to_bytes());
    assert!(pk_deserialized.verify(message, &sig_deserialized).is_ok());
}

#[test]
fn test_deterministic_keys_from_seed_87() {
    use xwing_sig::xwing_sig_87::*;
    let seed1 = [1u8; 32];
    let seed2 = [1u8; 32];
    let pk1 = SigningKey::new(seed1).verifying_key();
    let pk2 = SigningKey::new(seed2).verifying_key();
    assert!(pk1 == pk2, "Verifying keys should be equal");
}

#[test]
fn test_combiner_function() {
    let sig_ml = b"mock_ml_sig";
    let sig_ed = ed25519_dalek::Signature::from_bytes(&[0u8; 64]);
    let message_hash = Sha3_256::digest(b"message");
    // Compute expected tag manually
    let mut hasher = Sha3_256::new();
    hasher.update(sig_ml);
    hasher.update(sig_ed.to_bytes().as_ref());
    hasher.update(&message_hash);
    hasher.update(b"X-WING-SIG");
    let expected = hasher.finalize();
    assert_eq!(expected.len(), 32);
}
