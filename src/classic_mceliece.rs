use crate::field_ordering::FieldOrdering;
use crate::generator::Generator;
use crate::monic_polynomial::MonicPolynomial;
use crate::public_key::PublicKey;
use crate::secret_key::SecretKey;

pub struct ClassicMcEliece {}

impl ClassicMcEliece {
    pub const M: usize = 12;
    pub const N: usize = 3488;
    pub const T: usize = 64;
    pub const L: usize = 256;

    pub(crate) const Q: usize = 1 << Self::M;
    pub(crate) const K: usize = Self::N - Self::M * Self::T;

    pub(crate) const N_BYTES: usize = Self::N / 8;
    pub(crate) const L_BYTES: usize = Self::L / 8;
    pub(crate) const Q_BYTES: usize = Self::Q / 8;
    pub(crate) const K_BYTES: usize = Self::K / 8;

    pub(crate) const SIGMA_ONE_BYTES: usize = 2;
    pub(crate) const SIGMA_TWO_BYTES: usize = 4;

    pub(crate) const C0_BYTES: usize = (ClassicMcEliece::M * ClassicMcEliece::T) / 8;
    pub(crate) const C1_BYTES: usize = ClassicMcEliece::L_BYTES;
    pub const CIPHERTEXT_BYTES: usize = Self::C0_BYTES + Self::C1_BYTES;

    pub const SESSION_KEY_BYTES: usize = ClassicMcEliece::L_BYTES;

    #[inline]
    pub fn generate_keypair() -> (SecretKey, PublicKey) {
        use rand::RngCore;

        let mut seed = [0u8; ClassicMcEliece::L_BYTES];
        rand::thread_rng().fill_bytes(&mut seed);

        Self::generate_keypair_seeded(&seed)
    }

    pub(crate) fn generate_keypair_seeded(
        seed: &[u8; ClassicMcEliece::L_BYTES],
    ) -> (SecretKey, PublicKey) {
        let mut seed = *seed;

        loop {
            let mut s = [0u8; SecretKey::S_BYTES];
            let mut alpha_seed = [0u8; Self::SIGMA_TWO_BYTES * Self::Q];
            let mut g_seed = [0u8; Self::SIGMA_ONE_BYTES * Self::T];

            let mut generator = Generator::new(64, &seed);
            generator.squeeze(&mut s);
            generator.squeeze(&mut alpha_seed);
            generator.squeeze(&mut g_seed);

            let alpha = match FieldOrdering::new(&alpha_seed) {
                Some(alpha) => alpha,
                None => {
                    generator.squeeze(&mut seed);
                    continue;
                }
            };

            let g = match MonicPolynomial::irreducible(&g_seed) {
                Some(g) => g,
                None => {
                    generator.squeeze(&mut seed);
                    continue;
                }
            };

            let public_key = match PublicKey::generate(&g, &alpha) {
                Some(public_key) => public_key,
                None => {
                    generator.squeeze(&mut seed);
                    continue;
                }
            };

            return (SecretKey::new(&seed, &g, &alpha, &s), public_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::ClassicMcEliece;

    #[test]
    fn sanity_checks() {
        assert!(ClassicMcEliece::N <= ClassicMcEliece::Q);
        assert!(ClassicMcEliece::T >= 2);
        assert!(ClassicMcEliece::M * ClassicMcEliece::T < ClassicMcEliece::N);

        assert!(ClassicMcEliece::Q.is_power_of_two());

        assert!(ClassicMcEliece::SIGMA_ONE_BYTES * 8 >= ClassicMcEliece::M);
        assert!(ClassicMcEliece::SIGMA_TWO_BYTES * 8 >= ClassicMcEliece::M * 2);

        // Implementation-specific assumptions:

        assert_eq!(ClassicMcEliece::N_BYTES * 8, ClassicMcEliece::N);
        assert_eq!(ClassicMcEliece::L_BYTES * 8, ClassicMcEliece::L);
        assert_eq!(ClassicMcEliece::K_BYTES * 8, ClassicMcEliece::K);

        // TODO: is_multiple_of, name
        //assert_eq!(ClassicMcEliece::PK_ROW_BYTES * 8, ClassicMcEliece::PK_ROWS);

        assert!(u8::try_from(ClassicMcEliece::T).is_ok());
        // TODO: More?
    }
}
