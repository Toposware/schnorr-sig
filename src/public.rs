//! This module provides a `PublicKey` wrapping
//! struct around a `ProjectivePoint` element.

use super::private::PrivateKey;

use stark_curve::ProjectivePoint;

/// A private key
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey(pub(crate) ProjectivePoint);

impl PublicKey {
    /// Computes a public key from a provided private key
    pub fn from_private_key(sk: PrivateKey) -> Self {
        let pkey = ProjectivePoint::generator() * sk.0;

        PublicKey(pkey)
    }

    /// Converts this private key to an array of bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_compressed()
    }

    /// Constructs a private key from an array of bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ProjectivePoint::from_compressed(bytes).map(PublicKey)
    }
}