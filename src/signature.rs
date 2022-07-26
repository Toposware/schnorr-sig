// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module provides a Signature struct implementing
//! Schnorr signing and verification.

use crate::PUBLIC_KEY_LENGTH;

use super::error::SignatureError;
use super::{KeyPair, PrivateKey, PublicKey};
use super::{BASEFIELD_LENGTH, KEYED_SIGNATURE_LENGTH, SCALAR_LENGTH, SIGNATURE_LENGTH};

use bitvec::{order::Lsb0, view::AsBits};
use cheetah::BASEPOINT_TABLE;
use cheetah::{AffinePoint, CompressedPoint, Fp, Fp6, Scalar};
use hash::{
    rescue_64_12_8::RescueHash,
    traits::{Digest, Hasher},
};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable, CtOption};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

/// A Schnorr signature not attached to its message.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct Signature {
    /// The compressed random point generated during signing
    pub x: CompressedPoint,
    /// The exponent from the random scalar, the private key
    /// and the output of the hash seen as a `Scalar` element
    pub e: Scalar,
}

impl ConditionallySelectable for Signature {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Signature {
            x: CompressedPoint::conditional_select(&a.x, &b.x, choice),
            e: Scalar::conditional_select(&a.e, &b.e, choice),
        }
    }
}

/// A Schnorr signature not attached to its message, and the associated
/// signer's public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serialize", derive(Deserialize, Serialize))]
pub struct KeyedSignature {
    /// The public key to verify this signature against
    pub public_key: PublicKey,
    /// The signature
    pub signature: Signature,
}

impl PrivateKey {
    /// Computes a Schnorr signature.
    /// It is faster to sign with a `KeyPair` (containing the associated public key).
    pub fn sign(&self, message: &[u8], mut rng: impl CryptoRng + RngCore) -> Signature {
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(&BASEPOINT_TABLE * r);

        let h = hash_message(&r_point.get_x(), &PublicKey::from(self), message);
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits(h_bits);

        let e = r - self.0 * h_scalar;
        Signature {
            x: r_point.to_compressed(),
            e,
        }
    }

    /// Computes a Schnorr signature binded to its associated public key.
    /// It is faster to sign with a `KeyPair` (containing the associated public key).
    pub fn sign_and_bind_pkey(
        &self,
        message: &[u8],
        mut rng: impl CryptoRng + RngCore,
    ) -> KeyedSignature {
        let public_key = PublicKey::from(self);
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(&BASEPOINT_TABLE * r);

        let h = hash_message(&r_point.get_x(), &public_key, message);
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits(h_bits);

        let e = r - self.0 * h_scalar;
        let signature = Signature {
            x: r_point.to_compressed(),
            e,
        };

        KeyedSignature {
            public_key,
            signature,
        }
    }
}

impl KeyPair {
    /// Computes a Schnorr signature
    pub fn sign(&self, message: &[u8], mut rng: impl CryptoRng + RngCore) -> Signature {
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(&BASEPOINT_TABLE * r);

        let h = hash_message(&r_point.get_x(), &self.public_key, message);
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits(h_bits);

        let e = r - self.private_key.0 * h_scalar;
        Signature {
            x: r_point.to_compressed(),
            e,
        }
    }

    /// Computes a Schnorr signature binded to its associated public key.
    pub fn sign_and_bind_pkey(
        &self,
        message: &[u8],
        mut rng: impl CryptoRng + RngCore,
    ) -> KeyedSignature {
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(&BASEPOINT_TABLE * r);

        let h = hash_message(&r_point.get_x(), &self.public_key, message);
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits(h_bits);

        let e = r - self.private_key.0 * h_scalar;
        let signature = Signature {
            x: r_point.to_compressed(),
            e,
        };

        KeyedSignature {
            public_key: self.public_key,
            signature,
        }
    }

    /// Verifies a signature against a message and this key pair
    pub fn verify_signature(
        self,
        signature: &Signature,
        message: &[u8],
    ) -> Result<(), SignatureError> {
        signature.verify(message, &self.public_key)
    }
}

impl PublicKey {
    /// Verifies a signature against a message and this public key
    pub fn verify_signature(
        self,
        signature: &Signature,
        message: &[u8],
    ) -> Result<(), SignatureError> {
        signature.verify(message, &self)
    }
}

impl Signature {
    /// Verifies a Schnorr signature
    pub fn verify(self, message: &[u8], pkey: &PublicKey) -> Result<(), SignatureError> {
        if !bool::from(pkey.0.is_torsion_free()) {
            return Err(SignatureError::InvalidPublicKey);
        }

        let x_felt = Fp6::from_bytes(&self.x.0[0..48].try_into().unwrap()).unwrap();

        let h = hash_message(&x_felt, pkey, message);
        let h_bits = h.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits_vartime(h_bits);

        // Leverage faster scalar multiplication through
        // Straus-Shamir's trick with hardcoded base point table.
        let r = pkey
            .0
            .multiply_double_with_basepoint_vartime(&h_scalar.to_bytes(), &self.e.to_bytes());

        if r.get_x() == x_felt {
            Ok(())
        } else {
            Err(SignatureError::InvalidSignature)
        }
    }

    /// Converts this signature to an array of bytes
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut output = [0u8; SIGNATURE_LENGTH];
        output[0..BASEFIELD_LENGTH + 1].copy_from_slice(&self.x.to_bytes());
        output[BASEFIELD_LENGTH + 1..SIGNATURE_LENGTH].copy_from_slice(&self.e.to_bytes());

        output
    }

    /// Constructs a signature from an array of bytes
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> CtOption<Self> {
        let mut array = [0u8; BASEFIELD_LENGTH + 1];
        array.copy_from_slice(&bytes[0..BASEFIELD_LENGTH + 1]);
        let x = CompressedPoint::from_bytes(&array);

        let mut array = [0u8; SCALAR_LENGTH];
        array.copy_from_slice(&bytes[BASEFIELD_LENGTH + 1..SIGNATURE_LENGTH]);
        let e = Scalar::from_bytes(&array);

        e.and_then(|e| CtOption::new(Signature { x, e }, Choice::from(1u8)))
    }
}

impl KeyedSignature {
    /// Verifies a Schnorr signature
    pub fn verify(self, message: &[u8]) -> Result<(), SignatureError> {
        self.signature.verify(message, &self.public_key)
    }

    /// Converts this signature to an array of bytes
    pub fn to_bytes(&self) -> [u8; KEYED_SIGNATURE_LENGTH] {
        let mut output = [0u8; KEYED_SIGNATURE_LENGTH];
        output[0..PUBLIC_KEY_LENGTH].copy_from_slice(&self.public_key.to_bytes());
        output[PUBLIC_KEY_LENGTH..KEYED_SIGNATURE_LENGTH]
            .copy_from_slice(&self.signature.to_bytes());

        output
    }

    /// Constructs a signature from an array of bytes
    pub fn from_bytes(bytes: &[u8; KEYED_SIGNATURE_LENGTH]) -> CtOption<Self> {
        let mut array = [0u8; PUBLIC_KEY_LENGTH];
        array.copy_from_slice(&bytes[0..PUBLIC_KEY_LENGTH]);
        let public_key = PublicKey::from_bytes(&array);

        let mut array = [0u8; SIGNATURE_LENGTH];
        array.copy_from_slice(&bytes[PUBLIC_KEY_LENGTH..KEYED_SIGNATURE_LENGTH]);
        let signature = Signature::from_bytes(&array);

        let choice = public_key.is_some() & signature.is_some();

        CtOption::new(
            KeyedSignature {
                public_key: public_key.unwrap_or(PublicKey(AffinePoint::generator())),
                signature: signature.unwrap_or(Signature {
                    x: CompressedPoint([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
                    ]),
                    e: Scalar::zero(),
                }),
            },
            choice,
        )
    }
}

pub(crate) fn hash_message(point_coordinate: &Fp6, pkey: &PublicKey, message: &[u8]) -> [u8; 32] {
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    // Enforce that the message to be hashed fits the length of a
    // sequence of canonically encoded field elements.
    assert!(message.len() % 8 == 0);

    let mut data = <[Fp; 6] as From<&Fp6>>::from(point_coordinate).to_vec();
    data.extend_from_slice(&<[Fp; 6] as From<Fp6>>::from(pkey.0.get_x()));
    // Instead of serializing the public key and storing information of the y-coordinate into the
    // empty bits of the x-coordinate, we hash the lowest coefficient of y along with the x array.
    data.push(<[Fp; 6] as From<Fp6>>::from(pkey.0.get_y())[0]);

    let mut message_fp = Vec::with_capacity(message.len() / 8);
    for chunk in message.chunks(8) {
        message_fp.push(Fp::from_bytes(&chunk.try_into().unwrap()).unwrap());
    }
    data.extend_from_slice(&message_fp);

    let h = RescueHash::hash_field(&data);

    h.to_bytes()
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_conditional_selection() {
        let mut rng = OsRng;
        let a = PrivateKey::new(&mut rng);
        let b = PrivateKey::new(&mut rng);

        let message = [1u8; 32];
        let sig_a = a.sign(&message, &mut rng);
        let sig_b = b.sign(&message, &mut rng);

        assert_eq!(
            ConditionallySelectable::conditional_select(&sig_a, &sig_b, Choice::from(0u8)),
            sig_a
        );
        assert_eq!(
            ConditionallySelectable::conditional_select(&sig_a, &sig_b, Choice::from(1u8)),
            sig_b
        );
    }

    #[test]
    fn test_signature() {
        let mut rng = OsRng;

        let mut message = [0u8; 160];
        rng.fill_bytes(&mut message);

        let keypair = KeyPair::new(&mut rng);
        let skey = keypair.private_key;
        let pkey = keypair.public_key;

        // Regular signature

        let signature = skey.sign(&message, &mut rng);
        assert!(signature.verify(&message, &pkey).is_ok());
        assert!(pkey.verify_signature(&signature, &message).is_ok());

        let signature = keypair.sign(&message, &mut rng);
        assert!(keypair.verify_signature(&signature, &message).is_ok());

        // Keyed signature

        let signature = skey.sign_and_bind_pkey(&message, &mut rng);
        assert!(signature.verify(&message).is_ok());

        let signature = keypair.sign_and_bind_pkey(&message, &mut rng);
        assert!(signature.verify(&message).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let mut rng = OsRng;

        let mut message = [0u8; 160];
        rng.fill_bytes(&mut message);

        let skey = PrivateKey::new(&mut rng);
        let pkey = PublicKey::from(&skey);

        let signature = skey.sign(&message, &mut rng);

        {
            let mut wrong_message = message;
            wrong_message[0] = 42;
            assert!(signature.verify(&wrong_message, &pkey).is_err());
        }

        {
            let wrong_pkey = PublicKey(AffinePoint::generator());
            assert!(signature.verify(&message, &wrong_pkey).is_err());
        }

        {
            // Small order public key
            let wrong_pkey = PublicKey(AffinePoint::from_raw_coordinates([
                Fp6::from_raw_unchecked([
                    0x9bfcd3244afcb637,
                    0x39005e478830b187,
                    0x7046f1c03b42c6cc,
                    0xb5eeac99193711e5,
                    0x7fd272e724307b98,
                    0xcc371dd6dd5d8625,
                ]),
                Fp6::from_raw_unchecked([
                    0x9d03fdc216dfaae8,
                    0xbf4ade2a7665d9b8,
                    0xf08b022d5b3262b7,
                    0x2eaf583a3cf15c6f,
                    0xa92531e4b1338285,
                    0x5b8157814141a7a7,
                ]),
            ]));
            assert!(signature.verify(&message, &wrong_pkey).is_err());
        }

        {
            let wrong_signature_1 = Signature {
                x: CompressedPoint([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
                ]),
                e: signature.e,
            };
            assert!(wrong_signature_1.verify(&message, &pkey).is_err());
        }

        {
            let wrong_signature_2 = Signature {
                x: signature.x,
                e: Scalar::zero(),
            };
            assert!(wrong_signature_2.verify(&message, &pkey).is_err());
        }
    }

    #[test]
    fn test_encoding() {
        assert_eq!(
            Signature {
                x: CompressedPoint([
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                e: Scalar::zero(),
            }
            .to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        assert_eq!(
            Signature {
                x: CompressedPoint([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                e: Scalar::one(),
            }
            .to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        assert_eq!(
            KeyedSignature {
                public_key: PublicKey(AffinePoint::identity()),
                signature: Signature {
                    x: CompressedPoint([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                    e: Scalar::one(),
                },
            }
            .to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );

        // Test random keys encoding
        let mut rng = OsRng;

        for _ in 0..100 {
            let sig = Signature {
                x: AffinePoint::random(&mut rng).to_compressed(),
                e: Scalar::random(&mut rng),
            };
            let pkey = PublicKey(AffinePoint::random(&mut rng));

            let bytes = sig.to_bytes();
            assert_eq!(bytes.len(), SIGNATURE_LENGTH);

            assert_eq!(sig, Signature::from_bytes(&bytes).unwrap());

            let keyed_sig = KeyedSignature {
                signature: sig,
                public_key: pkey,
            };

            let bytes = keyed_sig.to_bytes();
            assert_eq!(bytes.len(), KEYED_SIGNATURE_LENGTH);

            assert_eq!(keyed_sig, KeyedSignature::from_bytes(&bytes).unwrap());
        }

        // Test invalid encoding
        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let recovered_sig = Signature::from_bytes(&bytes);
        assert!(bool::from(recovered_sig.is_none()))
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_serde() {
        let mut rng = OsRng;

        let mut message = [0u8; 160];
        rng.fill_bytes(&mut message);

        let skey = PrivateKey::new(&mut rng);

        let signature = skey.sign(&message, &mut rng);
        {
            let encoded = bincode::serialize(&signature).unwrap();
            let parsed: Signature = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, signature);

            // Check that the encoding is SIGNATURE_LENGTH (80) bytes exactly
            assert_eq!(encoded.len(), SIGNATURE_LENGTH);

            // Check that the encoding itself matches the usual one
            assert_eq!(
                signature,
                bincode::deserialize(&signature.to_bytes()).unwrap()
            );

            // Check that invalid encodings fail
            let signature = skey.sign(&message, &mut rng);
            let mut encoded = bincode::serialize(&signature).unwrap();
            encoded[SIGNATURE_LENGTH - 1] = 127;
            assert!(bincode::deserialize::<Signature>(&encoded).is_err());

            assert_eq!(
                format!("{:?}", bincode::deserialize::<Signature>(&encoded)),
                "Err(Custom(\"decompression failed\"))"
            );

            let encoded = bincode::serialize(&signature).unwrap();
            assert!(bincode::deserialize::<Signature>(&encoded[0..SIGNATURE_LENGTH - 1]).is_err());

            assert_eq!(
                format!(
                    "{:?}",
                    bincode::deserialize::<Signature>(&encoded[0..SIGNATURE_LENGTH - 1])
                ),
                "Err(Io(Kind(UnexpectedEof)))"
            );
        }

        let keyed_signature = KeyedSignature {
            public_key: PublicKey::from(&skey),
            signature,
        };
        {
            let encoded = bincode::serialize(&keyed_signature).unwrap();
            let parsed: KeyedSignature = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, keyed_signature);

            // Check that the encoding is KEYED_SIGNATURE_LENGTH (129) bytes exactly
            assert_eq!(encoded.len(), KEYED_SIGNATURE_LENGTH);

            // Check that the encoding itself matches the usual one
            assert_eq!(
                keyed_signature,
                bincode::deserialize(&keyed_signature.to_bytes()).unwrap()
            );

            // Check that invalid encodings fail
            let keyed_signature = skey.sign_and_bind_pkey(&message, &mut rng);
            let mut encoded = bincode::serialize(&keyed_signature).unwrap();
            encoded[KEYED_SIGNATURE_LENGTH - 1] = 127;
            assert!(bincode::deserialize::<KeyedSignature>(&encoded).is_err());

            assert_eq!(
                format!("{:?}", bincode::deserialize::<KeyedSignature>(&encoded)),
                "Err(Custom(\"decompression failed\"))"
            );

            let encoded = bincode::serialize(&keyed_signature).unwrap();
            assert!(bincode::deserialize::<KeyedSignature>(
                &encoded[0..KEYED_SIGNATURE_LENGTH - 1]
            )
            .is_err());

            assert_eq!(
                format!(
                    "{:?}",
                    bincode::deserialize::<KeyedSignature>(&encoded[0..SIGNATURE_LENGTH - 1])
                ),
                "Err(Io(Kind(UnexpectedEof)))"
            );
        }
    }
}
