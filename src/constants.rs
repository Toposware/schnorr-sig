// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module defines all constants used in this crate.

/// Scalar element length in bytes (serialized form)
pub const SCALAR_LENGTH: usize = 32;

/// Private key length in bytes (serialized form)
pub const PRIVATE_KEY_LENGTH: usize = SCALAR_LENGTH;

/// Basefield element length in bytes (serialized form)
pub const BASEFIELD_LENGTH: usize = 48;

/// Public key length in bytes (serialized form)
pub const PUBLIC_KEY_LENGTH: usize = BASEFIELD_LENGTH + 1;

/// Key pair length in bytes (serialized form)
pub const KEY_PAIR_LENGTH: usize = PRIVATE_KEY_LENGTH;

/// Signature length in bytes (serialized form)
pub const SIGNATURE_LENGTH: usize = BASEFIELD_LENGTH + 1 + SCALAR_LENGTH;

/// Keyed signature length in bytes (serialized form)
pub const KEYED_SIGNATURE_LENGTH: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH;

/// Chain code length for deriving keys
/// It could be only 16 but is set to 32 for safety.
pub const CHAIN_CODE_LENGTH: usize = 32;

/// Extended private key length in bytes (serialized form)
pub const EXTENDED_PRIVATE_KEY_LENGTH: usize = PRIVATE_KEY_LENGTH + CHAIN_CODE_LENGTH;

/// Extended public key length in bytes (serialized form)
pub const EXTENDED_PUBLIC_KEY_LENGTH: usize = PUBLIC_KEY_LENGTH + CHAIN_CODE_LENGTH;

/// Private key seed length in bytes
pub const PRIVATE_KEY_SEED_LENGTH: usize = 32;

/// Private key nonce length in bytes
pub const PRIVATE_KEY_NONCE_LENGTH: usize = 32;
