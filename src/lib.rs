#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#[cfg(not(target_env = "sgx"))]

#[macro_use]
extern crate sgx_tstd as std;

use std::prelude::v1::*;

pub mod error;
pub mod extended_key;
pub mod key_chain;
pub mod key_index;
pub mod traits;
pub mod chain_path;

pub use chain_path::{
    ChainPath, Error as ChainPathError, SubPath
};

pub use key_index::KeyIndex;
pub use extended_key::{
    ExtendedPrivKey, ExtendedPubKey
};