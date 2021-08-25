pub use crate::ChainPathError;
#[derive(Debug)]
pub enum HDWalletError {
    /// Index is out of range
    KeyIndexOutOfRange,
    ChainPathErr(ChainPathError),
    Secp256Error(secp256k1::Error),
    // Rng(rand_core::Error),
}

impl From<secp256k1::Error> for HDWalletError {
    fn from(err: secp256k1::Error) -> HDWalletError {
        HDWalletError::Secp256Error(err)
    }
}

impl From<ChainPathError> for HDWalletError {
    fn from(err: ChainPathError) -> HDWalletError {
        HDWalletError::ChainPathErr(err)
    }
}