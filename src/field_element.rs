use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::classic_mceliece::ClassicMcEliece;

#[derive(Clone, Copy, Debug)]
pub(crate) struct FieldElement(u16);

impl FieldElement {
    pub(crate) const MASK: u16 = (1 << ClassicMcEliece::M) - 1;

    pub(crate) const ZERO: Self = FieldElement(0);

    pub(crate) const ONE: Self = FieldElement(1);

    pub(crate) const TWO: Self = FieldElement(2);

    #[inline]
    pub(crate) fn is_valid(&self) -> bool {
        self.0 == self.0 & Self::MASK
    }

    #[inline]
    fn debug_is_valid(&self) {
        if cfg!(debug_assertions) {
            debug_assert!(self.is_valid());
        }
    }

    #[inline]
    pub(crate) const fn from_le_bytes(bytes: &[u8; 2]) -> Self {
        Self(u16::from_le_bytes(*bytes) & Self::MASK)
    }

    pub(crate) fn square(&self) -> Self {
        self.debug_is_valid();

        let mut x = self.0 as u32;

        x = (x | (x << 8)) & 0x00ff_00ff;
        x = (x | (x << 4)) & 0x0f0f_0f0f;
        x = (x | (x << 2)) & 0x3333_3333;
        x = (x | (x << 1)) & 0x5555_5555;

        let hi = x & 0x007f_c000;
        x ^= hi >> 9;
        x ^= hi >> 12;

        let lo = x & 0x0000_3000;
        x ^= lo >> 9;
        x ^= lo >> 12;

        (x as u16).into()
    }

    pub(crate) fn inverse(&self) -> Self {
        debug_assert!(self.0 != 0);
        self.debug_is_valid();

        let x_pow_0x001 = *self;
        let x_pow_0x003 = x_pow_0x001 * x_pow_0x001.square();
        let x_pow_0x00f = x_pow_0x003 * x_pow_0x003.square().square();
        let x_pow_0x0ff = x_pow_0x00f * x_pow_0x00f.square().square().square().square();
        let x_pow_0x3ff = x_pow_0x003 * x_pow_0x0ff.square().square();
        let x_pow_0x7ff = x_pow_0x001 * x_pow_0x3ff.square();

        x_pow_0x7ff.square() // x_pow_0xffe aka x^4.094
    }

    pub(crate) fn reverse_bits(&self) -> Self {
        let mut a = self.0;

        a = ((a & 0x00ff) << 8) | ((a & 0xff00) >> 8);
        a = ((a & 0x0f0f) << 4) | ((a & 0xf0f0) >> 4);
        a = ((a & 0x3333) << 2) | ((a & 0xcccc) >> 2);
        a = ((a & 0x5555) << 1) | ((a & 0xaaaa) >> 1);
        a >>= 4;

        Self(a)
    }

    #[inline]
    pub(crate) fn get_bit(&self, k: usize) -> u8 {
        debug_assert!(k < 12);
        (self.0 >> k) as u8 & 0b1
    }

    #[inline]
    pub(crate) fn is_zero_mask(&self) -> FieldElement {
        self.debug_is_valid();
        (((self.0 as u32).wrapping_sub(1) >> 19) as u16).into()
    }
}

impl From<u16> for FieldElement {
    #[inline]
    fn from(fe: u16) -> Self {
        Self(fe & Self::MASK)
    }
}

#[cfg(test)]
impl PartialEq for FieldElement {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.debug_is_valid();
        other.debug_is_valid();
        self.0 == other.0
    }
}

#[cfg(test)]
impl PartialEq<u16> for FieldElement {
    fn eq(&self, other: &u16) -> bool {
        self.debug_is_valid();
        Self(*other).debug_is_valid();
        self.0 == *other
    }
}

impl ConstantTimeEq for FieldElement {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.debug_is_valid();
        other.debug_is_valid();
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for FieldElement {
    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        self.debug_is_valid();
        other.debug_is_valid();
        self.0.conditional_assign(&other.0, choice);
    }

    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        a.debug_is_valid();
        b.debug_is_valid();
        FieldElement(u16::conditional_select(&a.0, &b.0, choice))
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl std::ops::Add for FieldElement {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        self.debug_is_valid();
        other.debug_is_valid();
        Self(self.0 ^ other.0)
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl std::ops::AddAssign for FieldElement {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl std::ops::Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        self.debug_is_valid();
        other.debug_is_valid();

        let lhs = self.0 as u32;
        let rhs = other.0 as u32;

        let mut x = (0..ClassicMcEliece::M)
            .map(|bit| lhs.wrapping_mul(rhs & (1 << bit)))
            .fold(0, |acc, x| acc ^ x);

        let hi = x & 0x007f_c000;
        x ^= hi >> 9;
        x ^= hi >> 12;

        let lo = x & 0x0000_3000;
        x ^= lo >> 9;
        x ^= lo >> 12;

        (x as u16).into()
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl std::ops::MulAssign for FieldElement {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl std::ops::Div for FieldElement {
    type Output = Self;

    #[inline]
    fn div(self, other: Self) -> Self {
        self * other.inverse()
    }
}
