use std::convert::TryInto;

use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::classic_mceliece::ClassicMcEliece;
use crate::field_element::FieldElement;

#[derive(Debug, Copy, Clone)]
pub(crate) struct MonicPolynomial(pub(crate) [FieldElement; ClassicMcEliece::T]);

impl MonicPolynomial {
    pub(crate) const BYTES: usize = ClassicMcEliece::SIGMA_ONE_BYTES * ClassicMcEliece::T;

    #[inline]
    fn from_bytes_unchecked(bytes: &[u8; Self::BYTES]) -> Self {
        let mut polynomial = Self([FieldElement::ZERO; ClassicMcEliece::T]);

        for (limb, bytes) in polynomial
            .0
            .iter_mut()
            .zip(bytes.chunks_exact(ClassicMcEliece::SIGMA_ONE_BYTES))
        {
            *limb = FieldElement::from_le_bytes(bytes.try_into().unwrap());
        }

        polynomial
    }

    #[inline]
    pub(crate) fn from_bytes(bytes: &[u8; Self::BYTES]) -> Option<Self> {
        let polynomial = Self::from_bytes_unchecked(bytes);

        if !polynomial.0.iter().all(|limb| limb.is_valid()) {
            return None;
        }

        Some(polynomial)
    }

    pub(crate) fn irreducible(seed: &[u8; Self::BYTES]) -> Option<Self> {
        debug_assert_eq!(ClassicMcEliece::SIGMA_ONE_BYTES, 2);

        let polynomial = Self::from_bytes_unchecked(seed);

        let mut matrix =
            [MonicPolynomial([FieldElement::ZERO; ClassicMcEliece::T]); ClassicMcEliece::T + 1];
        matrix[0].0[0] = FieldElement::ONE;
        matrix[1] = polynomial;

        for i in 1..ClassicMcEliece::T {
            let mut buffer = [FieldElement::ZERO; 2 * ClassicMcEliece::T - 1];
            mul(&matrix[i], &polynomial, &mut buffer);
            matrix[i + 1]
                .0
                .copy_from_slice(&buffer[..ClassicMcEliece::T]);
        }

        for j in 0..ClassicMcEliece::T {
            for k in (j + 1)..ClassicMcEliece::T {
                // TODO: Use is_zero_mask?
                let jj_is_zero = matrix[j].0[j].ct_eq(&FieldElement::ZERO);
                for row in matrix.iter_mut().take(ClassicMcEliece::T + 1).skip(j) {
                    row.0[j] += FieldElement::conditional_select(
                        &FieldElement::ZERO,
                        &row.0[k],
                        jj_is_zero,
                    );
                }
            }

            if matrix[j].0[j].vartime_is_zero() {
                return None;
            }

            let inverse = matrix[j].0[j].inverse();

            for row in matrix.iter_mut().take(ClassicMcEliece::T + 1).skip(j) {
                row.0[j] *= inverse;
            }

            for k in (0..ClassicMcEliece::T).filter(|k| *k != j) {
                let jk = matrix[j].0[k];
                for row in matrix.iter_mut().take(ClassicMcEliece::T + 1).skip(j) {
                    row.0[k] += row.0[j] * jk;
                }
            }
        }

        Some(*matrix.last().unwrap())
    }

    #[inline]
    pub(crate) fn reversing_explicitly_monic(
        polynomial: &[FieldElement; ClassicMcEliece::T + 1],
    ) -> Self {
        // debug_assert!(polynomial[0], FieldElement::ONE);

        let mut reversed = Self([FieldElement::ZERO; ClassicMcEliece::T]);

        for (r_limb, limb) in reversed.0.iter_mut().zip(polynomial.iter().rev()) {
            *r_limb = *limb;
        }

        reversed
    }

    pub(crate) fn evaluate_at(&self, a: FieldElement) -> FieldElement {
        self.0
            .iter()
            .rev()
            .skip(1)
            .fold(a + *self.0.last().unwrap(), |r, limb| r * a + *limb)
    }

    #[inline]
    pub(crate) fn root(
        &self,
        support: &[FieldElement; ClassicMcEliece::N],
    ) -> [FieldElement; ClassicMcEliece::N] {
        let mut output = [FieldElement::ZERO; ClassicMcEliece::N];

        for (output, support) in output.iter_mut().zip(support.iter()) {
            *output = self.evaluate_at(*support);
        }

        output
    }
}

fn mul(
    lhs: &MonicPolynomial,
    rhs: &MonicPolynomial,
    buffer: &mut [FieldElement; 2 * ClassicMcEliece::T - 1],
) {
    #[cfg(test)]
    assert!(buffer.iter().all(|x| x == &0));

    for (i, lhs) in lhs.0.iter().enumerate() {
        for (j, rhs) in rhs.0.iter().enumerate() {
            buffer[i + j] += *lhs * *rhs;
        }
    }

    for i in (ClassicMcEliece::T..buffer.len()).rev() {
        let limb = buffer[i];
        buffer[i - ClassicMcEliece::T + 3] += limb;
        buffer[i - ClassicMcEliece::T + 1] += limb;
        buffer[i - ClassicMcEliece::T + 0] += limb * FieldElement::TWO;
    }
}

#[cfg(test)]
impl PartialEq<MonicPolynomial> for MonicPolynomial {
    fn eq(&self, other: &MonicPolynomial) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
impl PartialEq<[u16; ClassicMcEliece::T]> for MonicPolynomial {
    fn eq(&self, other: &[u16; ClassicMcEliece::T]) -> bool {
        self.0.iter().zip(other).all(|(lhs, rhs)| lhs == rhs)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::generator::Generator;
    use crate::monic_polynomial::MonicPolynomial;

    #[test]
    fn irreducible() {
        let mut generator = Generator::new(
            64,
            &hex!("5b815c890117893d8bb8e886f63a78ce2d5f58342d703348cb95539e14b9a719"),
        );

        generator.skip(436 + 4 * 4096);

        let mut seed = [0u8; MonicPolynomial::BYTES];
        generator.squeeze(&mut seed);

        let g = MonicPolynomial::irreducible(&seed).unwrap();

        assert_eq!(
            g,
            [
                0x6f7, 0xe6e, 0x351, 0xe16, 0x076, 0xefe, 0x003, 0xfc0, 0xa67, 0x31a, 0x29a, 0xb7b,
                0x733, 0x24d, 0x981, 0xc4f, 0xbdd, 0xdd4, 0x09a, 0x190, 0x929, 0x4ad, 0x338, 0x0b0,
                0x094, 0xfc3, 0x1db, 0x4f4, 0x568, 0x99f, 0x87e, 0xfa2, 0x68f, 0xdb0, 0x8d4, 0x7f8,
                0x061, 0x86c, 0x538, 0xf8a, 0x05b, 0xf94, 0xa3a, 0x581, 0x2c5, 0xde4, 0xddf, 0x068,
                0xd8e, 0xdba, 0x855, 0x69c, 0x9e5, 0x849, 0x5e1, 0x7b6, 0x92c, 0x499, 0x1e7, 0xf98,
                0xa6c, 0xda5, 0x690, 0xd51,
            ]
        );
    }
}
