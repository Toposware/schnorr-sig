// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module provides a `PrivateKey` wrapping
//! struct around a `Scalar` element.

use super::KeyPair;
use super::PRIVATE_KEY_LENGTH;

use cheetah::Scalar;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable, CtOption};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

/// A private key
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct PrivateKey(pub(crate) Scalar);

impl From<&KeyPair> for PrivateKey {
    /// Extracts a private key from a key pair reference.
    fn from(key_pair: &KeyPair) -> PrivateKey {
        key_pair.private_key
    }
}

impl From<KeyPair> for PrivateKey {
    /// Extracts a private key from a key pair.
    fn from(key_pair: KeyPair) -> PrivateKey {
        key_pair.private_key
    }
}

impl ConditionallySelectable for PrivateKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        PrivateKey(Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl PrivateKey {
    /// Generates a new random private key
    pub fn new(mut rng: impl CryptoRng + RngCore) -> Self {
        let mut secret_scalar = Scalar::random(&mut rng);
        // This should not happen, but we never know..
        while bool::from(secret_scalar.is_zero()) {
            secret_scalar = Scalar::random(&mut rng);
        }

        PrivateKey(secret_scalar)
    }

    /// Generates a new private key from a provided scalar.
    ///
    /// If the source or generation method of the scalar is
    /// unknown, it is preferable to use the `PrivateKey:new`
    /// method instead.
    pub fn from_scalar(scalar: Scalar) -> Self {
        PrivateKey(scalar)
    }

    /// Converts this private key to an array of bytes
    pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Constructs a private key from an array of bytes
    pub fn from_bytes(bytes: &[u8; PRIVATE_KEY_LENGTH]) -> CtOption<Self> {
        Scalar::from_bytes(bytes).and_then(|s| CtOption::new(PrivateKey(s), !s.is_zero()))
    }

    /// Constructs a private key from a 64 bytes seed.
    pub fn from_seed(seed: &[u8; 64]) -> CtOption<Self> {
        let s = Scalar::from_bytes_wide(seed);
        CtOption::new(PrivateKey(s), !s.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_from_keypair() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let keypair = KeyPair::new(&mut rng);

            assert_eq!(keypair.private_key, PrivateKey::from(keypair));
            assert_eq!(keypair.private_key, PrivateKey::from(&keypair));
        }
    }

    #[test]
    fn test_conditional_selection() {
        let a = PrivateKey(Scalar::from(10u8));
        let b = PrivateKey(Scalar::from(42u8));

        assert_eq!(
            ConditionallySelectable::conditional_select(&a, &b, Choice::from(0u8)),
            a
        );
        assert_eq!(
            ConditionallySelectable::conditional_select(&a, &b, Choice::from(1u8)),
            b
        );
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            PrivateKey::from_scalar(Scalar::zero()).to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        assert_eq!(
            PrivateKey::from_scalar(Scalar::one()).to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        // Test random keys encodings
        let mut rng = OsRng;

        for _ in 0..100 {
            let key = PrivateKey::new(&mut rng);
            let bytes = key.to_bytes();
            assert_eq!(bytes.len(), PRIVATE_KEY_LENGTH);

            assert_eq!(key, PrivateKey::from_bytes(&bytes).unwrap());
        }

        // Test invalid encodings
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let recovered_key = PrivateKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));

        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        let recovered_key = PrivateKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));
    }

    #[test]
    fn test_from_seed() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let key = PrivateKey::new(&mut rng);
            let bytes = key.to_bytes();
            let mut seed = [0u8; 64];
            seed[0..32].copy_from_slice(&bytes);

            assert_eq!(key, PrivateKey::from_seed(&seed).unwrap());
        }

        let invalid_seed = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let recovered_key = PrivateKey::from_seed(&invalid_seed);
        assert!(bool::from(recovered_key.is_none()));
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;
        let skey = PrivateKey::new(&mut rng);
        let encoded = bincode::serialize(&skey).unwrap();
        let parsed: PrivateKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, skey);

        // Check that the encoding is PRIVATE_KEY_LENGTH (32) bytes exactly
        assert_eq!(encoded.len(), PRIVATE_KEY_LENGTH);

        // Check that the encoding itself matches the usual one
        assert_eq!(skey, bincode::deserialize(&skey.to_bytes()).unwrap());

        // Check that invalid encodings fail
        let skey = PrivateKey::new(&mut rng);
        let mut encoded = bincode::serialize(&skey).unwrap();
        encoded[PRIVATE_KEY_LENGTH - 1] = 127;
        assert!(bincode::deserialize::<PrivateKey>(&encoded).is_err());

        assert_eq!(
            format!("{:?}", bincode::deserialize::<PrivateKey>(&encoded)),
            "Err(Custom(\"decompression failed\"))"
        );

        let encoded = bincode::serialize(&skey).unwrap();
        assert!(bincode::deserialize::<PrivateKey>(&encoded[0..PRIVATE_KEY_LENGTH - 1]).is_err());

        assert_eq!(
            format!(
                "{:?}",
                bincode::deserialize::<PrivateKey>(&encoded[0..PRIVATE_KEY_LENGTH - 1])
            ),
            "Err(Io(Kind(UnexpectedEof)))"
        );
    }
}
