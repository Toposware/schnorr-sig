// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module provides a `PublicKey` wrapping
//! struct around an `AffinePoint` element.

use super::PrivateKey;
use super::PUBLIC_KEY_LENGTH;

use cheetah::{AffinePoint, CompressedPoint, BASEPOINT_TABLE};
use subtle::{Choice, ConditionallySelectable, CtOption};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

/// A private key
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct PublicKey(pub(crate) AffinePoint);

impl From<&PrivateKey> for PublicKey {
    /// Creates a public key from a private key reference.
    fn from(private_key: &PrivateKey) -> PublicKey {
        let public_key = &BASEPOINT_TABLE * private_key.0;
        PublicKey(public_key.into())
    }
}

impl From<PrivateKey> for PublicKey {
    /// Creates a public key from a private key.
    fn from(private_key: PrivateKey) -> PublicKey {
        (&private_key).into()
    }
}

impl ConditionallySelectable for PublicKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        PublicKey(AffinePoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl PublicKey {
    /// Converts this public key to an array of bytes
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_compressed().to_bytes()
    }

    /// Constructs a public key from an array of bytes
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> CtOption<Self> {
        AffinePoint::from_compressed(&CompressedPoint::from_bytes(bytes)).map(PublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheetah::Scalar;
    use rand_core::OsRng;

    #[test]
    fn test_from_private_key() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let skey = PrivateKey::new(&mut rng);
            let pkey = PublicKey((&BASEPOINT_TABLE * skey.0).into());

            assert_eq!(pkey, PublicKey::from(skey));
            assert_eq!(pkey, PublicKey::from(&skey));
        }
    }

    #[test]
    fn test_conditional_selection() {
        let a = PublicKey(AffinePoint::identity());
        let b = PublicKey(AffinePoint::generator());

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
            PublicKey::from(&PrivateKey::from_scalar(Scalar::zero())).to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128
            ]
        );

        // Test random keys encoding
        let mut rng = OsRng;

        for _ in 0..100 {
            let key = PublicKey::from(&PrivateKey::new(&mut rng));
            let bytes = key.to_bytes();
            assert_eq!(bytes.len(), PUBLIC_KEY_LENGTH);

            assert_eq!(key, PublicKey::from_bytes(&bytes).unwrap());
        }

        // Test invalid encodings
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let recovered_key = PublicKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));

        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let recovered_key = PublicKey::from_bytes(&bytes);
        assert!(bool::from(recovered_key.is_none()));
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;
        let pkey = PublicKey::from(&PrivateKey::new(&mut rng));
        let encoded = bincode::serialize(&pkey).unwrap();
        let parsed: PublicKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(parsed, pkey);

        // Check that the encoding is PUBLIC_KEY_LENGTH (49) bytes exactly
        assert_eq!(encoded.len(), PUBLIC_KEY_LENGTH);

        // Check that the encoding itself matches the usual one
        assert_eq!(pkey, bincode::deserialize(&pkey.to_bytes()).unwrap());

        // Check that invalid encodings fail
        let pkey = PublicKey::from(&PrivateKey::new(&mut rng));
        let mut encoded = bincode::serialize(&pkey).unwrap();
        encoded[PUBLIC_KEY_LENGTH - 1] = 255;
        assert!(bincode::deserialize::<PublicKey>(&encoded).is_err());

        assert_eq!(
            format!("{:?}", bincode::deserialize::<PublicKey>(&encoded)),
            "Err(Custom(\"decompression failed\"))"
        );

        let encoded = bincode::serialize(&pkey).unwrap();
        assert!(bincode::deserialize::<PublicKey>(&encoded[0..PUBLIC_KEY_LENGTH - 1]).is_err());

        assert_eq!(
            format!(
                "{:?}",
                bincode::deserialize::<PublicKey>(&encoded[0..PUBLIC_KEY_LENGTH - 1])
            ),
            "Err(Io(Kind(UnexpectedEof)))"
        );
    }
}
