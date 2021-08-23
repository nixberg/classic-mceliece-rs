use std::convert::TryInto;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

use crate::classic_mceliece::ClassicMcEliece;
use crate::control_bits::ControlBits;
use crate::field_element::FieldElement;
use crate::field_ordering::FieldOrdering;
use crate::monic_polynomial::MonicPolynomial;

pub struct SecretKey {
    #[allow(dead_code)] // TODO: Exporting fn.
    pub(crate) seed: [u8; Self::SEED_BYTES],
    pub(crate) g: MonicPolynomial,
    pub(crate) control_bits: ControlBits,
    pub(crate) s: [u8; Self::S_BYTES],
}

impl SecretKey {
    const SEED_BYTES: usize = ClassicMcEliece::L_BYTES;

    pub(crate) const S_BYTES: usize = ClassicMcEliece::N_BYTES;

    pub const BYTES: usize =
        Self::SEED_BYTES + 8 + MonicPolynomial::BYTES + ControlBits::BYTES + Self::S_BYTES;

    #[inline]
    pub(crate) fn new(
        seed: &[u8; Self::SEED_BYTES],
        g: &MonicPolynomial,
        alpha: &FieldOrdering,
        s: &[u8; Self::S_BYTES],
    ) -> Self {
        SecretKey {
            seed: *seed,
            g: *g,
            control_bits: alpha.into(),
            s: *s,
        }
    }

    // TODO: Return Option/Result.
    pub fn from_bytes(input: &[u8; Self::BYTES]) -> Self {
        let mut input = &input[..];

        let seed = input[..Self::SEED_BYTES].try_into().unwrap();
        input = &input[Self::SEED_BYTES..];

        assert_eq!(
            input[0..8],
            [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]
        );
        input = &input[8..];

        let g = MonicPolynomial::from_bytes(&input[..MonicPolynomial::BYTES].try_into().unwrap())
            .unwrap();
        input = &input[MonicPolynomial::BYTES..];

        let control_bits = ControlBits::from_bytes(input[..ControlBits::BYTES].try_into().unwrap());
        input = &input[ControlBits::BYTES..];

        let s = input[..Self::S_BYTES].try_into().unwrap();
        input = &input[Self::S_BYTES..];

        debug_assert!(input.is_empty());

        SecretKey {
            seed,
            g,
            control_bits,
            s,
        }
    }

    pub fn decapsulate(
        &self,
        ciphertext: &[u8; ClassicMcEliece::CIPHERTEXT_BYTES],
    ) -> [u8; ClassicMcEliece::SESSION_KEY_BYTES] {
        use crate::hash::*;

        let c0 = &ciphertext[..ClassicMcEliece::C0_BYTES];
        let c1 = &ciphertext[ClassicMcEliece::C0_BYTES..];

        let mut error = [0u8; ClassicMcEliece::N_BYTES];
        let mut success = self.decode(c0.try_into().unwrap(), &mut error);

        for (error, s) in error.iter_mut().zip(self.s.iter()) {
            error.conditional_assign(s, !success);
        }

        let mut c1_prime = [0u8; ClassicMcEliece::C1_BYTES];
        hash_2(&error, &mut c1_prime);

        success &= c1_prime.ct_eq(c1);

        for (error, s) in error.iter_mut().zip(self.s.iter()) {
            error.conditional_assign(s, !success);
        }

        let mut session_key = [0u8; ClassicMcEliece::SESSION_KEY_BYTES];

        hash_x(success.unwrap_u8(), &error, ciphertext, &mut session_key);

        session_key
    }

    fn decode(
        &self,
        c0: &[u8; ClassicMcEliece::C0_BYTES],
        error: &mut [u8; ClassicMcEliece::N_BYTES],
    ) -> Choice {
        let mut v = [0u8; ClassicMcEliece::N_BYTES]; // TODO: Name?
        v[..ClassicMcEliece::C0_BYTES].copy_from_slice(c0);

        // Compute syndrome and images:

        let support = self.control_bits.generate_support();

        let syndrome = synd(&self.g, &support, &v);

        let locator = berlenkamp_massey(&syndrome);

        let images = locator.root(&support);

        // Compute error and new syndrome:

        let mut weight: usize = 0;

        for (error, images) in error.iter_mut().zip(images.chunks_exact(8)) {
            *error = 0;
            for (i, image) in images.iter().enumerate() {
                let bit = image.is_zero_mask().get_bit(0);
                *error |= bit << i;
                weight += bit as usize;
            }
        }

        let other_syndrome = synd(&self.g, &support, error);

        weight.ct_eq(&ClassicMcEliece::T) & syndrome.ct_eq(&other_syndrome)
    }
}

fn synd(
    f: &MonicPolynomial,
    support: &[FieldElement; ClassicMcEliece::N],
    received_word: &[u8; ClassicMcEliece::N_BYTES],
) -> [FieldElement; 2 * ClassicMcEliece::T] {
    let mut syndrome = [FieldElement::ZERO; 2 * ClassicMcEliece::T];

    for i in 0..ClassicMcEliece::N {
        let c = (received_word[i / 8] as u16 >> (i % 8)) & 0b1;

        let e = f.evaluate_at(support[i]);
        let mut e_inv = e.square().inverse();

        for syndrome_limb in syndrome.iter_mut().take(2 * ClassicMcEliece::T) {
            *syndrome_limb += e_inv * FieldElement::from(c);
            e_inv *= support[i];
        }
    }

    syndrome
}

fn berlenkamp_massey(syndrome: &[FieldElement; 2 * ClassicMcEliece::T]) -> MonicPolynomial {
    let mut last_discrepancy = FieldElement::ONE;
    let mut length = 0;

    let mut bee = [FieldElement::ZERO; ClassicMcEliece::T + 1];
    let mut connection = [FieldElement::ZERO; ClassicMcEliece::T + 1];
    bee[1] = FieldElement::ONE;
    connection[0] = FieldElement::ONE;

    for n in 0..(2 * ClassicMcEliece::T) {
        let discrepancy = connection
            .iter()
            .zip(syndrome.iter().take(n + 1).rev())
            .fold(FieldElement::ZERO, |d, (c, s)| d + *c * *s);

        let discrepancy_is_zero = discrepancy.ct_eq(&FieldElement::ZERO);
        let do_step_5 = !discrepancy_is_zero & !(2 * length).ct_gt(&(n as u16));

        let connection_copy = connection;

        let adjustment_factor = discrepancy / last_discrepancy;

        for (c, b) in connection.iter_mut().zip(bee.iter()) {
            let mut adjustment = adjustment_factor * *b;
            adjustment.conditional_assign(&FieldElement::ZERO, discrepancy_is_zero);
            *c += adjustment;
        }

        {
            length.conditional_assign(&(n as u16 + 1 - length), do_step_5);

            // TODO: https://github.com/dalek-cryptography/subtle/issues/82
            for (bee, c) in bee.iter_mut().zip(connection_copy.iter()) {
                bee.conditional_assign(c, do_step_5);
            }

            last_discrepancy.conditional_assign(&discrepancy, do_step_5);
        }

        bee.rotate_right(1);
        bee[0] = FieldElement::ZERO;
    }

    MonicPolynomial::reversing_explicitly_monic(&connection)
}
