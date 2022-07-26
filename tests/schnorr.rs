// Copyright (c) 2021-2022 To&posware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Integration tests for Schnorr-sig.

use rand_core::{OsRng, RngCore};

use cheetah::Scalar;

use schnorr_sig::ChainCode;
use schnorr_sig::{ExtendedPrivateKey, ExtendedPublicKey, KeyPair, PrivateKey, PublicKey};
use schnorr_sig::{KeyedSignature, Signature};

use schnorr_sig::{
    EXTENDED_PRIVATE_KEY_LENGTH, EXTENDED_PUBLIC_KEY_LENGTH, KEYED_SIGNATURE_LENGTH,
    KEY_PAIR_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

use schnorr_sig::verify_batch;

#[test]
fn key_creation_and_conversion() {
    let mut rng = OsRng;

    let private_key = PrivateKey::new(&mut rng);
    let public_key = PublicKey::from(&private_key);

    let key_pair = KeyPair::from(&private_key);
    assert_eq!(key_pair.private_key, private_key);
    assert_eq!(key_pair.public_key, public_key);

    let key_pair = KeyPair::from(private_key);
    assert_eq!(key_pair.private_key, private_key);
    assert_eq!(key_pair.public_key, public_key);

    let private_key2 = PrivateKey::from(&key_pair);
    assert_eq!(private_key, private_key2);

    let private_key2 = PrivateKey::from(key_pair);
    assert_eq!(private_key, private_key2);

    let bytes = private_key.to_bytes();
    assert_eq!(
        private_key,
        PrivateKey::from_scalar(Scalar::from_bytes(&bytes).unwrap())
    );

    let mut seed = [0u8; 64];
    seed[0..32].copy_from_slice(&bytes);
    assert_eq!(private_key, PrivateKey::from_seed(&seed).unwrap());
    assert_eq!(key_pair, KeyPair::from_seed(&seed).unwrap());
}
#[test]
fn signing_and_verification_of_single_signature() {
    let mut rng = OsRng;

    {
        let signer_private_key = PrivateKey::new(&mut rng);
        let signer_public_key = signer_private_key.into();
        let message = b"A random message";

        let signature = signer_private_key.sign(message, &mut rng);
        assert!(signature.verify(message, &signer_public_key).is_ok());

        let signature_bytes = signature.to_bytes();
        assert_eq!(signature_bytes.len(), SIGNATURE_LENGTH);
        assert_eq!(signature, Signature::from_bytes(&signature_bytes).unwrap());

        let keyed_signature = signer_private_key.sign_and_bind_pkey(message, &mut rng);
        assert!(keyed_signature.verify(message).is_ok());

        let signature_bytes = keyed_signature.to_bytes();
        assert_eq!(signature_bytes.len(), KEYED_SIGNATURE_LENGTH);
        assert_eq!(
            keyed_signature,
            KeyedSignature::from_bytes(&signature_bytes).unwrap()
        );

        #[cfg(feature = "serialize")]
        {
            let encoded = bincode::serialize(&signature).unwrap();
            let parsed: Signature = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, signature);

            let encoded = bincode::serialize(&keyed_signature).unwrap();
            let parsed: KeyedSignature = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, keyed_signature);
        }
    }

    {
        let signer = KeyPair::new(&mut rng);
        let signer_private_key = signer.private_key;
        let signer_public_key = signer.public_key;
        let message = b"A random message";

        let signature = signer.sign(message, &mut rng);
        assert!(signature.verify(message, &signer_public_key).is_ok());
        assert!(signer.verify_signature(&signature, message).is_ok());
        assert!(signer_public_key
            .verify_signature(&signature, message)
            .is_ok());

        let keyed_signature = signer.sign_and_bind_pkey(message, &mut rng);
        assert!(keyed_signature.verify(message).is_ok());

        let private_key_bytes = signer_private_key.to_bytes();
        let public_key_bytes = signer_public_key.to_bytes();
        let keypair_bytes = signer.to_bytes();

        assert_eq!(private_key_bytes.len(), PRIVATE_KEY_LENGTH);
        assert_eq!(
            signer_private_key,
            PrivateKey::from_bytes(&private_key_bytes).unwrap()
        );

        assert_eq!(public_key_bytes.len(), PUBLIC_KEY_LENGTH);
        assert_eq!(
            signer_public_key,
            PublicKey::from_bytes(&public_key_bytes).unwrap()
        );

        assert_eq!(keypair_bytes.len(), KEY_PAIR_LENGTH);
        assert_eq!(signer, KeyPair::from_bytes(&keypair_bytes).unwrap());

        #[cfg(feature = "serialize")]
        {
            let encoded = bincode::serialize(&signer_private_key).unwrap();
            let parsed: PrivateKey = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, signer_private_key);

            let encoded = bincode::serialize(&signer_public_key).unwrap();
            let parsed: PublicKey = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, signer_public_key);

            let encoded = bincode::serialize(&signer).unwrap();
            let parsed: KeyPair = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, signer);
        }
    }
}

#[test]
fn batch_verification_of_three_signatures() {
    let mut rng = OsRng;

    let signer_1 = KeyPair::new(&mut rng);
    let signer_2 = KeyPair::new(&mut rng);
    let signer_3 = signer_1;
    let message_1 = b"A random message to sign";
    let message_2 = b"Another message to sign!";
    let message_3 = b"And once again another message from the others!!";
    let signer_1_public_key = signer_1.public_key;
    let signer_2_public_key = signer_2.public_key;
    let signer_3_public_key = signer_3.public_key;

    let signature_1 = signer_1.sign(message_1, &mut rng);
    let signature_2 = signer_2.sign(message_2, &mut rng);
    let signature_3 = signer_3.sign(message_3, &mut rng);

    // Individual verifications
    assert!(signature_1.verify(message_1, &signer_1_public_key).is_ok());
    assert!(signature_2.verify(message_2, &signer_2_public_key).is_ok());
    assert!(signature_3.verify(message_3, &signer_3_public_key).is_ok());

    assert!(verify_batch(
        &[signature_1, signature_2, signature_3],
        &[
            signer_1_public_key,
            signer_2_public_key,
            signer_3_public_key
        ],
        &[message_1, message_2, message_3],
        &mut rng
    )
    .is_ok());
}

#[test]
fn key_derivation() {
    let mut rng = OsRng;

    {
        let key_pair = KeyPair::new(&mut rng);
        let private_key = key_pair.private_key;
        let public_key = key_pair.public_key;

        let mut cc = [0u8; 32];
        rng.fill_bytes(&mut cc);
        let index = [1, 0, 0, 0];
        let (private_child, private_child_chaincode) =
            private_key.derive_private(ChainCode(cc), &index);
        let (public_child, public_child_chaincode) =
            public_key.derive_public(ChainCode(cc), &index);

        assert_eq!(PublicKey::from(private_child), public_child);
        assert_eq!(private_child_chaincode, public_child_chaincode);
    }

    {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let master_private_key = ExtendedPrivateKey::generate_master_key(&seed).unwrap();
        let master_public_key = ExtendedPublicKey::from_extended_private_key(&master_private_key);

        let mut cc = [0u8; 32];
        rng.fill_bytes(&mut cc);

        // Non-hardened derivation
        let index = [1, 0, 0, 0];
        let private_child = master_private_key.derive_private(&index).unwrap();
        let public_child = master_private_key.derive_public(&index).unwrap();
        let public_child2 = master_public_key.derive_normal_public(&index).unwrap();

        assert_eq!(
            ExtendedPublicKey::from_extended_private_key(&private_child),
            public_child
        );
        assert_eq!(public_child, public_child2);

        // Hardened derivation
        let index = [255, 255, 255, 255];
        let private_child = master_private_key.derive_private(&index).unwrap();
        let public_child = master_private_key.derive_public(&index).unwrap();

        assert_eq!(
            ExtendedPublicKey::from_extended_private_key(&private_child),
            public_child
        );

        let private_child_bytes = private_child.to_bytes();
        let public_child_bytes = public_child.to_bytes();

        assert_eq!(private_child_bytes.len(), EXTENDED_PRIVATE_KEY_LENGTH);
        assert_eq!(
            private_child,
            ExtendedPrivateKey::from_bytes(&private_child_bytes).unwrap()
        );

        assert_eq!(public_child_bytes.len(), EXTENDED_PUBLIC_KEY_LENGTH);
        assert_eq!(
            public_child,
            ExtendedPublicKey::from_bytes(&public_child_bytes).unwrap()
        );

        #[cfg(feature = "serialize")]
        {
            let encoded = bincode::serialize(&private_child).unwrap();
            let parsed: ExtendedPrivateKey = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, private_child);

            let encoded = bincode::serialize(&public_child).unwrap();
            let parsed: ExtendedPublicKey = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed, public_child);
        }
    }
}
