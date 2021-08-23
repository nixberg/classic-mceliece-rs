mod classic_mceliece;
mod control_bits;
mod field_element;
mod field_ordering;
mod generator;
mod hash;
mod monic_polynomial;
mod public_key;
mod secret_key;

pub use crate::classic_mceliece::ClassicMcEliece;
pub use crate::public_key::PublicKey;
pub use crate::secret_key::SecretKey;

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::{ClassicMcEliece, PublicKey, SecretKey};

    #[test]
    #[ignore = "slow in debug; stack overflow"]
    fn nist_kats() {
        #[derive(serde::Deserialize)]
        struct KAT {
            count: usize,
            seed: String,
            pk: String,
            sk: String,
            ct: String,
            ss: String,
            e: String,
        }

        let kats: Vec<KAT> = serde_json::from_slice(include_bytes!("../tests/kats.json")).unwrap();

        for kat in kats {
            println!("NIST KAT {}", kat.count);

            let expected_sk_bytes = hex::decode(&kat.sk).unwrap();
            assert_eq!(SecretKey::BYTES, expected_sk_bytes.len());

            let expected_pk_bytes = hex::decode(&kat.pk).unwrap();
            assert_eq!(PublicKey::BYTES, expected_pk_bytes.len());

            let expected_ct_bytes = hex::decode(&kat.ct).unwrap();
            assert_eq!(ClassicMcEliece::CIPHERTEXT_BYTES, expected_ct_bytes.len());

            let expected_ss_bytes = hex::decode(&kat.ss).unwrap();
            assert_eq!(ClassicMcEliece::SESSION_KEY_BYTES, expected_ss_bytes.len());

            let expected_e_bytes = hex::decode(&kat.e).unwrap();
            assert_eq!(ClassicMcEliece::N_BYTES, expected_e_bytes.len());

            let seed = hex::decode(&kat.seed).unwrap();

            let (secret_key, public_key) =
                ClassicMcEliece::generate_keypair_seeded(&seed.try_into().unwrap());

            {
                let expected_sk = SecretKey::from_bytes(&expected_sk_bytes.try_into().unwrap());

                assert_eq!(secret_key.seed, expected_sk.seed);
                assert_eq!(secret_key.g, expected_sk.g);
                assert_eq!(secret_key.control_bits, expected_sk.control_bits);
                assert_eq!(secret_key.s, expected_sk.s);

                assert_eq!(public_key.0, expected_pk_bytes[..]);
            }

            {
                let (ciphertext, session_key) =
                    public_key.encapsulate_deterministic(&expected_e_bytes.try_into().unwrap());

                assert_eq!(ciphertext, expected_ct_bytes[..]);
                assert_eq!(session_key, expected_ss_bytes[..]);

                assert_eq!(secret_key.decapsulate(&ciphertext), expected_ss_bytes[..]);
            }
        }
    }
}
