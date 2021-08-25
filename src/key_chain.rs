use crate::{error::HDWalletError, ChainPath, ChainPathError, ExtendedPrivKey, KeyIndex, SubPath};
use std::result;

type Result<T> = result::Result<T, HDWalletError>;

/// KeyChain derivation info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation {
    /// depth, 0 if it is master key
    pub depth: u8,
    /// parent key
    pub parent_key: Option<ExtendedPrivKey>,
    /// key_index which used with parent key to derive this key
    pub key_index: Option<KeyIndex>,
}

impl Derivation {
    pub fn master() -> Self {
        Derivation {
            depth: 0,
            parent_key: None,
            key_index: None,
        }
    }
}

impl Default for Derivation {
    fn default() -> Self {
        Derivation::master()
    }
}

/// KeyChain is used for derivation HDKey from master_key and chain_path.
pub trait KeyChain {
    fn derive_private_key(
        &self,
        chain_path: ChainPath,
    ) -> Result<(ExtendedPrivKey, Derivation)>;
}