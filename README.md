[![Rust](https://github.com/nixberg/classic-mceliece-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/nixberg/classic-mceliece-rs/actions/workflows/rust.yml)

# classic-mceliece-rs

Experimental, do not use.

Rust implementation of [`kem/mceliece348864`](https://classic.mceliece.org/).

## Notes

- `FixedWeight` implemented as `seeded_fixed_weight`.

## Usage

```Rust
use classic_mceliece::ClassicMcEliece;

let (secret_key, public_key) = ClassicMcEliece::generate_keypair();

let (ciphertext, expected_session_key) = public_key.encapsulate();

let session_key = secret_key.decapsulate(&ciphertext);

assert_eq!(session_key, expected_session_key);
```
