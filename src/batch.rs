// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module provides an implementation of batched signature
//! verification and an implementation of "Non-interactive
//! half-aggregation of EdDSA and variants of Schnorr signatures".

use cheetah::AffinePoint;
use cheetah::Fp6;
use cheetah::Scalar;
use cheetah::BASEPOINT_TABLE;

use super::error::SignatureError;
use super::signature::hash_message;
use super::{PublicKey, Signature};

use bitvec::{order::Lsb0, view::AsBits};
use rand_core::{CryptoRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};

/// Verifies a batch of signatures with their associated public_keys
pub fn verify_batch(
    signatures: &[Signature],
    public_keys: &[PublicKey],
    messages: &[&[u8]],
    mut rng: impl CryptoRng + RngCore,
) -> Result<(), SignatureError> {
    assert!(
        signatures.len() == public_keys.len(),
        "We should have the same number of signatures than public keys"
    );
    assert!(
        messages.len() == public_keys.len(),
        "We should have the same number of messages than public keys"
    );

    let (scalars, hashes) =
        generate_batch_coefficients(signatures, public_keys, messages, &mut rng);

    verify_prepared_batch(scalars, hashes, signatures, public_keys)
}

/// Prepares a batch verification of Schnorr signatures
/// It computes the random challenges for each signature and the random scalars to
/// scale the public keys.
#[allow(non_snake_case)]
fn generate_batch_coefficients(
    signatures: &[Signature],
    public_keys: &[PublicKey],
    messages: &[&[u8]],
    mut rng: impl CryptoRng + RngCore,
) -> (Vec<Scalar>, Vec<Scalar>) {
    let hashes: Vec<Scalar> = signatures
        .iter()
        .zip(public_keys)
        .zip(messages)
        .map(|((s, k), m)| {
            let x_felt = Fp6::from_bytes(&s.x.0[0..48].try_into().unwrap()).unwrap();
            let h = hash_message(&x_felt, k, m);
            let h_bits = h.as_bits::<Lsb0>();

            Scalar::from_bits_vartime(h_bits)
        })
        .collect();

    let scalars: Vec<Scalar> = signatures
        .iter()
        .map(|_| Scalar::random(&mut rng))
        .collect();

    (scalars, hashes)
}

/// Verifies a batch with a set of random scalars and hash outputs
fn verify_prepared_batch(
    scalars: Vec<Scalar>,
    mut hashes: Vec<Scalar>,
    signatures: &[Signature],
    public_keys: &[PublicKey],
) -> Result<(), SignatureError> {
    // Compute the linear combination of the random scalars with the
    // signatures. This is used to multiply the curve basepoint.
    let lin_comb: Scalar = signatures
        .iter()
        .map(|sig| sig.e)
        .zip(scalars.iter())
        .map(|(e, s)| s * e)
        .sum();
    let scaled_basepoint = BASEPOINT_TABLE.multiply_vartime(&lin_comb.to_bytes());

    let points: Vec<AffinePoint> = signatures
        .iter()
        .map(|sig| AffinePoint::from_compressed(&sig.x).unwrap())
        .collect();

    // Multiply each hash by the random value
    for (h, s) in hashes.iter_mut().zip(scalars.iter()) {
        *h = &*h * s;
    }
    let key_points: Vec<AffinePoint> = public_keys.into_iter().map(|k| k.0).collect();

    // Convert scalars and hash outputs to byte slices
    let scalar_bytes: Vec<[u8; 32]> = scalars.into_iter().map(|s| s.to_bytes()).collect();
    let hashes_bytes: Vec<[u8; 32]> = hashes.into_iter().map(|h| h.to_bytes()).collect();

    // Compute the multi-scalar multiplication on both side of the equation
    let left = AffinePoint::multiply_many_vartime(&points, &scalar_bytes);
    let right = AffinePoint::multiply_many_vartime(&key_points, &hashes_bytes);
    // Add to the sum of keys the scaled basepoint computed earlier
    let right = AffinePoint::from(scaled_basepoint.add_mixed_unchecked(&right));

    if left.get_x() == right.get_x() {
        Ok(())
    } else {
        Err(SignatureError::InvalidSignature)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::KeyPair;
    use rand_core::OsRng;

    #[test]
    fn verify_one_signature() {
        let mut rng = OsRng;
        let message = b"Message1";

        let keypair: KeyPair = KeyPair::new(&mut rng);
        let signature = keypair.sign(message, rng);
        let public_key = keypair.public_key;

        assert!(public_key.verify_signature(&signature, message).is_ok());
        assert!(verify_batch(&[signature], &[public_key], &[message], &mut rng).is_ok());
        assert!(verify_batch(&[signature], &[public_key], &[message], &mut rng).is_ok());
    }

    #[test]
    fn verify_five_signatures() {
        let mut rng = OsRng;
        let messages: [&[u8]; 5] = [
            b"Message1",
            b"Message2",
            b"Message3",
            b"Message4",
            b"Message5",
        ];
        let mut keypairs: Vec<KeyPair> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();

        for i in 0..messages.len() {
            let mut keypair: KeyPair = KeyPair::new(&mut rng);
            while !bool::from(keypair.public_key.0.get_y().lexicographically_largest()) {
                keypair = KeyPair::new(&mut rng);
            }
            if i == 3 || i == 4 {
                keypair = keypairs[0].clone();
            }
            signatures.push(keypair.sign(messages[i], rng));
            keypairs.push(keypair);
        }
        let mut public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public_key).collect();

        assert!(verify_batch(&signatures[..], &public_keys[..], &messages[..], &mut rng).is_ok());

        public_keys.swap(1, 2);
        assert!(verify_batch(&signatures[..], &public_keys[..], &messages[..], &mut rng).is_err());
    }
}
