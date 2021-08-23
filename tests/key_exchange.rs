use classic_mceliece::ClassicMcEliece;

#[test]
#[ignore = "slow in debug; stack overflow"]
fn key_exchange() {
    let (secret_key, public_key) = ClassicMcEliece::generate_keypair();

    let (ciphertext, expected_session_key) = public_key.encapsulate();

    let session_key = secret_key.decapsulate(&ciphertext);

    assert_eq!(session_key, expected_session_key);
}
