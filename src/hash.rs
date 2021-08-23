use crate::classic_mceliece::ClassicMcEliece;

fn hash(
    domain: u8,
    error: &[u8; ClassicMcEliece::N_BYTES],
    ciphertext: Option<&[u8; ClassicMcEliece::CIPHERTEXT_BYTES]>,
    output: &mut [u8; ClassicMcEliece::SESSION_KEY_BYTES],
) {
    use std::io::Read;

    use digest::{ExtendableOutput, Update};

    let mut hasher = sha3::Shake256::default();

    hasher.update(&[domain]);
    hasher.update(error);
    if let Some(ciphertext) = ciphertext {
        hasher.update(ciphertext);
    }

    hasher.finalize_xof().read_exact(output).unwrap();
}

#[inline]
pub(crate) fn hash_x(
    domain: u8,
    error: &[u8; ClassicMcEliece::N_BYTES],
    ciphertext: &[u8; ClassicMcEliece::CIPHERTEXT_BYTES],
    session_key: &mut [u8; ClassicMcEliece::SESSION_KEY_BYTES],
) {
    debug_assert!(domain == 0 || domain == 1);
    hash(domain, error, Some(ciphertext), session_key);
}

#[inline]
pub(crate) fn hash_2(
    error: &[u8; ClassicMcEliece::N_BYTES],
    c1: &mut [u8; ClassicMcEliece::L_BYTES],
) {
    hash(2, error, None, c1);
}
