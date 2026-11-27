//! Port of `NewCBCTransformer` from
//! `k8s.io/apiserver/pkg/storage/value/encrypt/aes/aes.go` (AES-CBC with
//! PKCS#7 padding and a random IV prepended to the ciphertext).
//!
//! CBC is not authenticated: the [`Context`] is ignored, as upstream.
//!
//! Deliberate difference: upstream indexes `result[len(result)-1]` without a
//! length check, which panics when the stored data is exactly one IV and no
//! ciphertext. Here that case fails closed with the "invalid PKCS7 data" error.

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::{NoPadding, Pkcs7};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use super::aes::{random_nonce, Block};
use super::{Context, Error, Read, Transformer, Write};

/// `aes.BlockSize`.
const BLOCK_SIZE: usize = 16;

const ERR_INVALID_BLOCK_SIZE: &str = "the stored data is not a multiple of the block size";
const ERR_INVALID_PKCS7_DATA: &str = "invalid PKCS7 data (empty or not padded)";
const ERR_INVALID_PKCS7_PADDING: &str = "invalid padding on input";

/// `cbc`: implements encryption at rest of the provided values given a
/// `cipher.Block` algorithm.
struct Cbc {
    block: Block,
}

/// `NewCBCTransformer` takes the given block cipher and performs encryption
/// and decryption on the given data.
pub fn new_cbc_transformer(block: &Block) -> Box<dyn Transformer> {
    Box::new(Cbc {
        block: block.clone(),
    })
}

impl Read for Cbc {
    fn transform_from_storage(
        &self,
        data: &[u8],
        _ctx: &dyn Context,
    ) -> Result<(Vec<u8>, bool), Error> {
        if data.len() < BLOCK_SIZE {
            return Err(Error::new(
                "the stored data was shorter than the required size",
            ));
        }
        let (iv, data) = data.split_at(BLOCK_SIZE);
        if data.len() % BLOCK_SIZE != 0 {
            return Err(Error::new(ERR_INVALID_BLOCK_SIZE));
        }

        let key = self.block.key();
        let mut result = data.to_vec();
        let bad = |_| Error::new("crypto/cipher: invalid key or IV");
        match key.len() {
            16 => cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(bad)?
                .decrypt_padded_mut::<NoPadding>(&mut result),
            24 => cbc::Decryptor::<Aes192>::new_from_slices(key, iv)
                .map_err(bad)?
                .decrypt_padded_mut::<NoPadding>(&mut result),
            _ => cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(bad)?
                .decrypt_padded_mut::<NoPadding>(&mut result),
        }
        .map_err(|_| Error::new(ERR_INVALID_BLOCK_SIZE))?;

        // remove and verify PKCS#7 padding for CBC
        let Some(&c) = result.last() else {
            return Err(Error::new(ERR_INVALID_PKCS7_DATA));
        };
        let padding_size = c as usize;
        if padding_size == 0 || padding_size > result.len() {
            return Err(Error::new(ERR_INVALID_PKCS7_DATA));
        }
        let size = result.len() - padding_size;
        if result[size..].iter().any(|&b| b != c) {
            return Err(Error::new(ERR_INVALID_PKCS7_PADDING));
        }
        result.truncate(size);
        Ok((result, false))
    }
}

impl Write for Cbc {
    fn transform_to_storage(&self, data: &[u8], _ctx: &dyn Context) -> Result<Vec<u8>, Error> {
        let mut iv = [0u8; BLOCK_SIZE];
        random_nonce(&mut iv).map_err(|_| Error::new("unable to read sufficient random bytes"))?;

        let key = self.block.key();
        let bad = |_| Error::new("crypto/cipher: invalid key or IV");
        let ct = match key.len() {
            16 => cbc::Encryptor::<Aes128>::new_from_slices(key, &iv)
                .map_err(bad)?
                .encrypt_padded_vec_mut::<Pkcs7>(data),
            24 => cbc::Encryptor::<Aes192>::new_from_slices(key, &iv)
                .map_err(bad)?
                .encrypt_padded_vec_mut::<Pkcs7>(data),
            _ => cbc::Encryptor::<Aes256>::new_from_slices(key, &iv)
                .map_err(bad)?
                .encrypt_padded_vec_mut::<Pkcs7>(data),
        };
        let mut result = Vec::with_capacity(BLOCK_SIZE + ct.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ct);
        Ok(result)
    }
}
