use secp256k1::{PublicKey, Secp256k1, SecretKey};
use ring::hmac::{Context, Key, HMAC_SHA512};
use std::vec::Vec;
use std::result;
use crate::{
    error::HDWalletError,
    traits::{Deserialize, Serialize},
};
use crate::key_index::KeyIndex;

type Result<T> = result::Result<T, HDWalletError>;

/// Random entropy, part of extended key.
type ChainCode = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrivKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

impl ExtendedPrivKey {
    /// Generate an ExtendedPrivKey from seed
    pub fn with_seed(seed: &[u8]) -> Result<ExtendedPrivKey> {
        let signature = {
            let signing_key = Key::new(HMAC_SHA512, b"Enclave seed");
            let mut h = Context::with_key(&signing_key);
            h.update(&seed);
            h.sign()    // Finalizes the HMAC calculation and returns the HMAC value. sign consumes the context so it cannot be (mis-)used after sign has been called.
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(&Secp256k1::new(), key)?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }

    fn sign_normal_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.private_key);
        h.update(&public_key.serialize());
        h.update(&index.to_be_bytes());
        h.sign()
    }

    /// Derive a child key from ExtendedPrivKey.
    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<ExtendedPrivKey> {
        if !key_index.is_valid() {
            return Err(HDWalletError::KeyIndexOutOfRange);
        }
        let signature = match key_index {
            // KeyIndex::Hardened(index) => self.sign_hardended_key(index),     // TODO
            KeyIndex::Normal(index) => self.sign_normal_key(index),
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let mut private_key = SecretKey::from_slice(&Secp256k1::new(), key)?;
        private_key.add_assign(&Secp256k1::new(), &self.private_key)?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }
}

/// ExtendedPubKey is used for public child key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPubKey {
    pub public_key: PublicKey,
    pub chain_code: ChainCode,
}

impl ExtendedPubKey {
    /// Derive public normal child key from ExtendedPubKey,
    /// will return error if key_index is a hardened key.
    pub fn derive_public_key(&self, key_index: KeyIndex) -> Result<ExtendedPubKey> {
        if !key_index.is_valid() {
            return Err(HDWalletError::KeyIndexOutOfRange);
        }

        let index = match key_index {
            KeyIndex::Normal(i) => i,
            // KeyIndex::Hardened(_) => return Err(HDWalletError::KeyIndexOutOfRange),  // TODO
        };

        let signature = {
            let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
            let mut h = Context::with_key(&signing_key);
            h.update(&self.public_key.serialize());
            h.update(&index.to_be_bytes());
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(&Secp256k1::new(), key)?;
        let mut public_key = self.public_key;
        public_key.add_exp_assign(&Secp256k1::verification_only(), &private_key)?;
        Ok(ExtendedPubKey {
            public_key,
            chain_code: chain_code.to_vec(),
        })
    }

    /// ExtendedPubKey from ExtendedPrivKey
    pub fn from_private_key(extended_key: &ExtendedPrivKey) -> Self {
        let public_key =
            PublicKey::from_secret_key(&Secp256k1::signing_only(), &extended_key.private_key);
        ExtendedPubKey {
            public_key,
            chain_code: extended_key.chain_code.clone(),
        }
    }
}

impl Serialize<Vec<u8>> for ExtendedPrivKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = self.private_key[..].to_vec();
        buf.extend(&self.chain_code);
        buf
    }
}
impl Deserialize<&[u8], HDWalletError> for ExtendedPrivKey {
    fn deserialize(data: &[u8]) -> Result<Self> {
        let private_key = SecretKey::from_slice(&Secp256k1::new(), &data[..32])?;
        let chain_code = data[32..].to_vec();
        Ok(ExtendedPrivKey {
            private_key,
            chain_code,
        })
    }
}

impl Serialize<Vec<u8>> for ExtendedPubKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = self.public_key.serialize().to_vec();
        buf.extend(&self.chain_code);
        buf
    }
}

impl Deserialize<&[u8], HDWalletError> for ExtendedPubKey {
    fn deserialize(data: &[u8]) -> Result<Self> {
        let public_key = PublicKey::from_slice(&Secp256k1::new(), &data[..33])?;
        let chain_code = data[33..].to_vec();
        Ok(ExtendedPubKey {
            public_key,
            chain_code,
        })
    }
}
