use crate::classic_mceliece::ClassicMcEliece;

pub(crate) struct Generator {
    reader: sha3::Sha3XofReader,
}

impl Generator {
    pub(crate) fn new(domain: u8, seed: &[u8; ClassicMcEliece::L_BYTES]) -> Self {
        use digest::{ExtendableOutput, Update};

        let mut hasher = sha3::Shake256::default();
        hasher.update(&[domain]);
        hasher.update(seed);

        Generator {
            reader: hasher.finalize_xof(),
        }
    }

    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        digest::XofReader::read(&mut self.reader, output);
    }

    #[cfg(test)]
    pub(crate) fn squeeze_boxed(&mut self, count: usize) -> Box<[u8]> {
        digest::XofReader::read_boxed(&mut self.reader, count)
    }

    #[cfg(test)]
    pub(crate) fn skip(&mut self, count: u64) {
        use std::io::{copy, sink, Read};
        copy(&mut self.reader.by_ref().take(count), &mut sink()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::generator::Generator;

    #[test]
    fn it_works() {
        let mut generator = Generator::new(
            64,
            &hex!("72b94de13a3abbc0b7b09358512756a7e8ba529f40a37da7d1c40cc8c021b6e0"),
        );

        generator.skip(3271);

        assert_eq!(
            generator.squeeze_boxed(32)[..],
            hex!("2e8694765420bf9f9f7454737dad2639e951e181450090cfd8fa81ae14b39e8c")
        );
    }
}
