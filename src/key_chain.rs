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

pub struct DefaultKeyChain {
    master_key: ExtendedPrivKey,
}

impl DefaultKeyChain {
    pub fn new(master_key: ExtendedPrivKey) -> Self {
        DefaultKeyChain { master_key }
    }
}

impl KeyChain for DefaultKeyChain {
    fn derive_private_key(
        &self,
        chain_path: ChainPath,
    ) -> Result<(ExtendedPrivKey, Derivation)> {
        let mut iter = chain_path.iter();
        // chain_path must start with root
        if iter.next() != Some(Ok(SubPath::Root)) {
            return Err(ChainPathError::Invalid.into());
        }
        let mut key = self.master_key.clone();
        let mut depth = 0;
        let mut parent_key = None;
        let mut key_index = None;
        for sub_path in iter {
            match sub_path? {
                SubPath::Child(child_key_index) => {
                    depth += 1;
                    key_index = Some(child_key_index);
                    let child_key = key.derive_private_key(child_key_index)?;
                    parent_key = Some(key);
                    key = child_key;
                }
                _ => return Err(ChainPathError::Invalid.into()),
            }
        }
        Ok((
            key,
            Derivation {
                depth,
                parent_key,
                key_index,
            },
        ))
    }
}