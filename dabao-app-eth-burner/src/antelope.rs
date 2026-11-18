//! Antelope (XPR Network, Telos, EOS, ...) signing: the digest, the "canonical"
//! signature the nodes insist on, and the `PUB_K1_` / `SIG_K1_` text forms.
//!
//! The device signs blind: it hashes the serialized transaction it is given
//! and never looks inside it.
use k256::ecdsa::hazmat::SignPrimitive;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use signer_core::DerivationPath;

/// SLIP-44 coin type of EOS, which Antelope wallets (and the Ledger EOS app)
/// use for every Antelope chain: keys live under `m/44'/194'`.
pub const COIN_TYPE: u32 = 194;

/// Whether `path` is under `m/44'/194'`. The Antelope commands refuse any
/// other path, so they can never use an Ethereum key.
pub fn path_allowed(path: &DerivationPath) -> bool {
    matches!(&path.components[..], [purpose, coin, ..]
        if purpose.hardened && purpose.index == 44 && coin.hardened && coin.index == COIN_TYPE)
}

/// What an Antelope node verifies a transaction signature against:
/// SHA-256(chain id || serialized transaction || 32 zero bytes). The zeros
/// stand for "no context-free data".
pub fn signing_digest(chain_id: &[u8; 32], transaction: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(chain_id);
    h.update(transaction);
    h.update([0u8; 32]);
    h.finalize().into()
}

/// The nodes' `is_canonical` (libfc): neither `r` nor `s` may start with a set
/// top bit, or with a zero byte followed by a byte without one.
fn is_canonical(r: &[u8], s: &[u8]) -> bool {
    let ok = |n: &[u8]| n[0] & 0x80 == 0 && !(n[0] == 0 && n[1] & 0x80 == 0);
    ok(r) && ok(s)
}

/// Sign `digest`, as the 65 bytes Antelope uses: `31 + recovery id || r || s`.
///
/// About half of all signatures aren't canonical. The nonce is deterministic
/// (RFC 6979), so a counter is mixed into it until the signature is one.
pub fn sign(key: &SigningKey, digest: &[u8; 32]) -> Option<[u8; 65]> {
    let secret: &k256::Scalar = key.as_nonzero_scalar().as_ref();
    for attempt in 0u8..=255 {
        let extra = [attempt];
        // the first try is plain RFC 6979
        let extra = if attempt == 0 { &extra[..0] } else { &extra[..] };
        let Ok((sig, Some(recid))) = secret.try_sign_prehashed_rfc6979::<Sha256>(&(*digest).into(), extra) else {
            continue;
        };
        let (r, s) = (sig.r().to_bytes(), sig.s().to_bytes());
        if !is_canonical(&r, &s) {
            continue;
        }
        // never hand out a signature that doesn't recover to this key
        if VerifyingKey::recover_from_prehash(digest, &sig, recid).ok().as_ref() != Some(key.verifying_key()) {
            return None;
        }
        let mut out = [0u8; 65];
        out[0] = 27 + 4 + recid.to_byte();
        out[1..33].copy_from_slice(&r);
        out[33..].copy_from_slice(&s);
        return Some(out);
    }
    None
}

/// The public key that made `signature` over `digest` (compressed SEC1).
pub fn recover(signature: &[u8; 65], digest: &[u8; 32]) -> Option<[u8; 33]> {
    let recid = RecoveryId::from_byte(signature[0].checked_sub(31)?)?;
    let sig = Signature::from_slice(&signature[1..]).ok()?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recid).ok()?;
    key.to_encoded_point(true).as_bytes().try_into().ok()
}

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // little-endian base-58 digits
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in &data[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// `prefix` + base58(data || first 4 bytes of RIPEMD-160(data || "K1")).
fn k1_text(prefix: &str, data: &[u8]) -> String {
    let mut h = Ripemd160::new();
    h.update(data);
    h.update(b"K1");
    let mut bytes = data.to_vec();
    bytes.extend_from_slice(&h.finalize()[..4]);
    format!("{prefix}{}", base58(&bytes))
}

/// `PUB_K1_...` for a compressed secp256k1 public key.
pub fn public_key_text(compressed: &[u8; 33]) -> String {
    k1_text("PUB_K1_", compressed)
}

/// `SIG_K1_...` for a signature from [`sign`].
pub fn signature_text(signature: &[u8; 65]) -> String {
    k1_text("SIG_K1_", signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    fn compressed(key: &SigningKey) -> [u8; 33] {
        key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap()
    }

    #[test]
    fn base58_matches_known_values() {
        assert_eq!(base58(b""), "");
        assert_eq!(base58(&[0, 0, 1]), "112");
        assert_eq!(base58(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
    }

    #[test]
    fn only_paths_under_44h_194h_are_allowed() {
        let path = |c: &[(u32, bool)]| DerivationPath {
            components: c.iter().map(|&(index, hardened)| signer_core::ChildNumber { index, hardened }).collect(),
        };
        assert!(path_allowed(&path(&[(44, true), (194, true), (0, true), (0, false), (0, false)])));
        assert!(!path_allowed(&path(&[(44, true), (60, true), (0, true), (0, false), (0, false)])));
        assert!(!path_allowed(&path(&[(44, true), (194, false), (0, true)])));
        assert!(!path_allowed(&path(&[(44, true)])));
        assert!(!path_allowed(&path(&[])));
    }

    #[test]
    fn digest_is_chain_id_transaction_and_32_zeros() {
        let mut all = vec![7u8; 32];
        all.extend_from_slice(b"transaction");
        all.extend_from_slice(&[0; 32]);
        let expected: [u8; 32] = Sha256::digest(&all).into();
        assert_eq!(signing_digest(&[7; 32], b"transaction"), expected);
    }

    #[test]
    fn signatures_are_canonical_and_recover_to_the_key() {
        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let mut retried = 0;
        for i in 0..64u8 {
            let digest: [u8; 32] = Sha256::digest([i]).into();
            let sig = sign(&key, &digest).unwrap();
            assert!((31..35).contains(&sig[0]));
            assert!(is_canonical(&sig[1..33], &sig[33..]));
            assert_eq!(recover(&sig, &digest), Some(compressed(&key)));
            assert_eq!(sign(&key, &digest), Some(sig), "deterministic");
            // did the plain RFC 6979 signature have to be replaced?
            let plain: Signature = {
                use k256::ecdsa::signature::hazmat::PrehashSigner;
                key.sign_prehash(&digest).unwrap()
            };
            retried += (plain.to_bytes()[..] != sig[1..]) as u32;
        }
        assert!(retried > 8, "the retry loop was exercised ({retried} of 64)");
    }

    // Values made with @wharfkit/antelope (tools/antelope/vectors.mjs).
    const SECRET: &str = "d2653ff7cbb2d8ff129ac27ef5781ce68b2558c41a74af1f2ddca635cbeef07d";
    const PUBLIC: &str = "PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63";

    #[test]
    fn text_forms_match_wharfkit() {
        let key = SigningKey::from_slice(&unhex::<32>(SECRET)).unwrap();
        assert_eq!(public_key_text(&compressed(&key)), PUBLIC);
        for (digest, signature, text) in WHARFKIT_SIGNATURES {
            let sig: [u8; 65] = unhex(signature);
            assert_eq!(signature_text(&sig), *text);
            assert_eq!(recover(&sig, &unhex(digest)), Some(compressed(&key)));
        }
    }

    /// (digest, signature as hex, signature as text), signed by Wharfkit with `SECRET`.
    #[rustfmt::skip]
    const WHARFKIT_SIGNATURES: &[(&str, &str, &str)] = &[
        ("b525c0e88a2bdd3328b035ce4db2156f8ce15d2723718edf86ddf664faa726b2", "1f4c99f3498abdf1c6b6a7319785054d9bba5ff28f9b88ea6526b7dc5e8c81af5a4aa5ec90c9054ad7d47b06d57ba648c71a216eaccf63e09853673f0fef65c834", "SIG_K1_K5H2nGWtHmxar8YYAbyvogZHpfgnKBUvPRuPiRU3zi2HdWDuhxyZeTBCTcEmVJjCa2kWCtY7jbN8Fc5qmRip6T8nBWpUNf"),
        ("60036271fa788f50955f5ff1f31b3beb5228eca561f0109626960395f4a3f864", "1f6e6d55a99c913bbe3ee15e0c6745f534f6e564254189538f5cc2bc210314990543b07df6273de8dbdb3697df0976e48b0f12b2a4016badef665d67095bf7e75a", "SIG_K1_K9hhiX5PSxR93euaM4RUYLW1WymhLVFKyzDfiJrw9kKP5SDX8guPrTXTnTwSNysaRjNvX7xFT8VJMYrfYjXQRZoXAuwDzU"),
        ("6ed447eaff344949409eb38542b633936ea420d35e07323ff8b1c555845a3d84", "202cd7125fce0e81922889025bb56c86040ec33bc383e66aa7c9b1c855fefe9e4203f0da76a04f0543c60ff50d11a8783dc53504dbec5dc8035d0343602cd940d4", "SIG_K1_KacZpfHjQ5Pr5XoevpxmjvnmngMXaopaEaiAEuTufRNWFekMbWJ7zDjtvnxg1etvk9dyo1U67sNBkRzppiwQXepB1uLbGc"),
    ];
}
