use std::result;
use crate::error::HDWalletError;

type Result<T> = result::Result<T, HDWalletError>;

const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648; // 2 ** 31

/// KeyIndex indicates the key type and index of a child key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyIndex {
    /// Normal key, index range is from 0 to 2 ** 31 - 1
    Normal(u32),

    // Hardened(u32),   // TODO: Hardened key, index range is from 2 ** 31 to 2 ** 32 - 1
}

impl KeyIndex {
    /// Check index range.
    pub fn is_valid(self) -> bool {
        match self {
            KeyIndex::Normal(i) => i < HARDENED_KEY_START_INDEX,
            // KeyIndex::Hardened(i) => i >= HARDENED_KEY_START_INDEX,  // TODO
        }
    }

    /// Generate KeyIndex from raw index value.
    pub fn from_index(i: u32) -> Result<Self> {
        if i < HARDENED_KEY_START_INDEX {
            Ok(KeyIndex::Normal(i))
        } else {
            // Ok(KeyIndex::Hardened(i))    // TODO
            return Err(HDWalletError::KeyIndexOutOfRange);
        }
    }
}

impl From<u32> for KeyIndex {
    fn from(index: u32) -> Self {
        KeyIndex::from_index(index).expect("KeyIndex")
    }
}