use std::convert::TryInto;

use crate::classic_mceliece::ClassicMcEliece;
use crate::field_element::FieldElement;
use crate::field_ordering::FieldOrdering;
use crate::generator::Generator;
use crate::monic_polynomial::MonicPolynomial;

pub struct PublicKey(pub(crate) [u8; PublicKey::BYTES]);

impl PublicKey {
    const ROWS: usize = ClassicMcEliece::M * ClassicMcEliece::T;
    const ROW_BYTES: usize = ClassicMcEliece::K_BYTES;

    pub const BYTES: usize = Self::ROWS * Self::ROW_BYTES;

    pub(crate) fn generate(g: &MonicPolynomial, alpha: &FieldOrdering) -> Option<Self> {
        let mut matrix = [[0u8; ClassicMcEliece::N_BYTES]; PublicKey::ROWS];

        {
            // Filling the matrix:

            let support = alpha.generate_support();

            let mut inv = g.root(&support);

            for inv in inv.iter_mut() {
                *inv = inv.inverse();
            }

            for i in 0..ClassicMcEliece::T {
                for (j, inv) in inv.chunks_exact(8).enumerate() {
                    for k in 0..ClassicMcEliece::M {
                        matrix[i * ClassicMcEliece::M + k][j] = inv
                            .iter()
                            .rev()
                            .map(|inv| inv.get_bit(k))
                            .fold(0, |byte, bit| (byte << 1) | bit);
                    }
                }

                for (inv, support) in inv.iter_mut().zip(support.iter()) {
                    *inv *= *support;
                }
            }
        }

        // Gaussian elimination:

        for i in 0..(PublicKey::ROWS / 8) {
            for j in 0..8 {
                let row = i * 8 + j;

                if row >= PublicKey::ROWS {
                    break;
                }

                for k in (row + 1)..PublicKey::ROWS {
                    let mut mask = matrix[row][i] ^ matrix[k][i];
                    mask >>= j;
                    mask &= 1;
                    mask = mask.wrapping_neg();

                    for c in 0..ClassicMcEliece::N_BYTES {
                        matrix[row][c] ^= matrix[k][c] & mask;
                    }
                }

                if ((matrix[row][i] >> j) & 0b1) == 0 {
                    return None;
                }

                for k in (0..PublicKey::ROWS).filter(|k| *k != row) {
                    let mut mask = matrix[k][i] >> j;
                    mask &= 1;
                    mask = mask.wrapping_neg();

                    for c in 0..ClassicMcEliece::N_BYTES {
                        matrix[k][c] ^= matrix[row][c] & mask;
                    }
                }
            }
        }

        let mut public_key = PublicKey([0; Self::BYTES]);

        for (pk_row, matrix_row) in public_key
            .0
            .chunks_exact_mut(PublicKey::ROW_BYTES)
            .zip(matrix.iter())
        {
            pk_row.copy_from_slice(&matrix_row[(PublicKey::ROWS / 8)..]); // TODO: Ok?
        }

        Some(public_key)
    }

    #[inline]
    // TODO: Test!
    pub fn encapsulate(
        &self,
    ) -> (
        [u8; ClassicMcEliece::CIPHERTEXT_BYTES],
        [u8; ClassicMcEliece::SESSION_KEY_BYTES],
    ) {
        use rand::RngCore;

        let mut seed = [0u8; ClassicMcEliece::L_BYTES];
        rand::thread_rng().fill_bytes(&mut seed);

        let error = seeded_fixed_weight(&seed);

        self.encapsulate_deterministic(&error)
    }

    pub(crate) fn encapsulate_deterministic(
        &self,
        error: &[u8; ClassicMcEliece::N_BYTES],
    ) -> (
        [u8; ClassicMcEliece::CIPHERTEXT_BYTES],
        [u8; ClassicMcEliece::SESSION_KEY_BYTES],
    ) {
        use crate::hash::*;

        let mut ciphertext = [0u8; ClassicMcEliece::CIPHERTEXT_BYTES];

        let c0 = &mut ciphertext[..ClassicMcEliece::C0_BYTES];
        self.encode(error, c0.try_into().unwrap());

        let c1 = &mut ciphertext[ClassicMcEliece::C0_BYTES..];
        hash_2(error, c1.try_into().unwrap());

        let mut session_key = [0u8; ClassicMcEliece::SESSION_KEY_BYTES];
        hash_x(1, error, &ciphertext, &mut session_key);

        (ciphertext, session_key)
    }

    fn encode(
        &self,
        error: &[u8; ClassicMcEliece::N_BYTES],
        syndrome: &mut [u8; ClassicMcEliece::C0_BYTES],
    ) {
        debug_assert!(syndrome.iter().all(|s| *s == 0));

        let lhs_error = &error[..(ClassicMcEliece::N_BYTES - Self::ROW_BYTES)];
        let rhs_error = &error[(ClassicMcEliece::N_BYTES - Self::ROW_BYTES)..];

        for ((syndrome_byte, lhs_error_byte), eight_rows) in syndrome
            .iter_mut()
            .zip(lhs_error)
            .zip(self.0.chunks_exact(8 * Self::ROW_BYTES))
        {
            for (selected_bit, row) in eight_rows.chunks_exact(Self::ROW_BYTES).enumerate() {
                let byte = (1 << selected_bit) & lhs_error_byte;

                let byte = row
                    .iter()
                    .zip(rhs_error)
                    .map(|(r, e)| r & e)
                    .fold(byte, |acc, b| acc ^ b);

                *syndrome_byte |= parity_bit(byte) << selected_bit;
            }
        }
    }
}

// TODO: Test!
fn seeded_fixed_weight(seed: &[u8; ClassicMcEliece::L_BYTES]) -> [u8; ClassicMcEliece::N_BYTES] {
    let mut seed = *seed;
    let mut ind = [0u16; ClassicMcEliece::T];

    loop {
        let mut bytes = [0u8; 2 * 2 * ClassicMcEliece::T]; // TODO: asd

        let mut generator = Generator::new(65, &seed);
        generator.squeeze(&mut bytes);
        generator.squeeze(&mut seed);

        let mut nums = [0u16; 2 * ClassicMcEliece::T];
        for (num, bytes) in nums.iter_mut().zip(bytes.chunks_exact(2)) {
            *num = u16::from_le_bytes(bytes.try_into().unwrap()) & FieldElement::MASK;
        }

        // moving and counting indices in the correct range

        let mut count = 0;

        for num in nums.iter() {
            if count >= ClassicMcEliece::T {
                // TODO: Ok?
                break;
            }
            if *num < ClassicMcEliece::N as u16 {
                ind[count] = *num;
                count += 1;
            }
        }

        if count < ClassicMcEliece::T {
            continue;
        }

        let mut no_repetition_found = true;

        for i in 1..ClassicMcEliece::T {
            for j in 0..i {
                if ind[i] == ind[j] {
                    no_repetition_found = false;
                }
            }
        }

        if no_repetition_found {
            break;
        }
    }

    let mut vals = [0u8; ClassicMcEliece::T];
    for (val, ind) in vals.iter_mut().zip(ind.iter()) {
        *val = 1 << (*ind & 7) as u8;
    }

    let mut error = [0u8; ClassicMcEliece::N_BYTES];

    for (i, e) in error.iter_mut().enumerate() {
        for (ind, val) in ind.iter().zip(vals.iter()) {
            *e |= val & eq_mask(i as u32, *ind as u32 >> 3);
        }
    }

    error
}

fn eq_mask(x: u32, y: u32) -> u8 {
    let mut mask = x ^ y;
    mask = mask.wrapping_sub(1);
    mask >>= 31;
    mask = mask.wrapping_neg();
    mask as u8
}

fn parity_bit(byte: u8) -> u8 {
    [4, 2, 1].iter().fold(byte, |acc, s| acc ^ (acc >> s)) & 0b1
}
