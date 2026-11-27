//! Port of `k8s.io/apiserver/pkg/storage/value/encrypt/secretbox/secretbox.go`:
//! transforms values for storage at rest using XSalsa20 and Poly1305.
//!
//! Uses a standard 24 byte nonce (placed at the beginning of the cipher text)
//! from the OS RNG. The context is not used for authentication, as upstream.

use crypto_secretbox::aead::generic_array::GenericArray;
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;

use super::aes::random_nonce;
use super::{Context, Error, Read, Transformer, Write};

/// `nonceSize`.
const NONCE_SIZE: usize = 24;
/// `secretbox.Overhead`: the Poly1305 tag.
const OVERHEAD: usize = 16;

struct SecretboxTransformer {
    key: [u8; 32],
}

/// `NewSecretboxTransformer` takes the given key and performs encryption and
/// decryption on the given data.
pub fn new_secretbox_transformer(key: [u8; 32]) -> Box<dyn Transformer> {
    Box::new(SecretboxTransformer { key })
}

impl Read for SecretboxTransformer {
    fn transform_from_storage(
        &self,
        data: &[u8],
        _ctx: &dyn Context,
    ) -> Result<(Vec<u8>, bool), Error> {
        if data.len() < OVERHEAD + NONCE_SIZE {
            return Err(Error::new(
                "the stored data was shorter than the required size",
            ));
        }
        let (nonce, data) = data.split_at(NONCE_SIZE);
        let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&self.key));
        // Message text is upstream's, verbatim (sic).
        let result = cipher
            .decrypt(GenericArray::from_slice(nonce), data)
            .map_err(|_| Error::new("output array was not large enough for encryption"))?;
        Ok((result, false))
    }
}

impl Write for SecretboxTransformer {
    fn transform_to_storage(&self, data: &[u8], _ctx: &dyn Context) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; NONCE_SIZE];
        random_nonce(&mut nonce)
            .map_err(|_| Error::new("unable to read sufficient random bytes"))?;
        let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&self.key));
        let sealed = cipher
            .encrypt(GenericArray::from_slice(&nonce), data)
            .map_err(|_| Error::new("secretbox: seal failed"))?;
        let mut out = Vec::with_capacity(NONCE_SIZE + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}
