//! The AES layer, for the audio the relay produces itself.
//!
//! A player's audio arrives already sealed: every client holds the same key,
//! so the relay copies the bytes and rewrites the secret. A source the server
//! feeds (a jukebox, an addon's stream) has no client to seal for it, so the
//! frame is sealed here, with the same `AES/CBC/PKCS5Padding` and the same
//! `IV || ciphertext` layout the clients use (`pv-client`'s `crypto.rs`).

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

type Encryptor = cbc::Encryptor<aes::Aes128>;

/// The voice key, as the 16 bytes `ConfigPacket.encryption` carries.
#[derive(Clone)]
pub(crate) struct Cipher {
    key: [u8; 16],
}

impl Cipher {
    pub(crate) fn new(key: [u8; 16]) -> Self {
        Cipher { key }
    }

    /// `IV || AES/CBC/PKCS5Padding(data)`, the form a client decrypts.
    pub(crate) fn seal(&self, data: &[u8]) -> Vec<u8> {
        use rsa::rand_core::{OsRng, RngCore};
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let cipher = Encryptor::new(&self.key.into(), &iv.into());
        let mut out = iv.to_vec();
        out.extend_from_slice(&cipher.encrypt_padded_vec_mut::<Pkcs7>(data));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{block_padding::Pkcs7 as Pad, BlockDecryptMut, KeyIvInit};

    fn open(key: &[u8; 16], sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < 32 || !sealed.len().is_multiple_of(16) {
            return None;
        }
        let (iv, body) = sealed.split_at(16);
        type Decryptor = cbc::Decryptor<aes::Aes128>;
        Decryptor::new(&(*key).into(), iv.into())
            .decrypt_padded_vec_mut::<Pad>(body)
            .ok()
    }

    #[test]
    fn a_sealed_frame_opens_with_the_same_key_only() {
        let key = *b"0123456789abcdef";
        let cipher = Cipher::new(key);
        let sealed = cipher.seal(b"an opus frame from a jukebox");

        assert_eq!(
            open(&key, &sealed).as_deref(),
            Some(b"an opus frame from a jukebox".as_slice())
        );
        // Whole blocks, with the IV in front: what the client's reader expects.
        assert_eq!(sealed.len() % 16, 0);
        assert!(sealed.len() >= 32);
        assert_eq!(open(b"fedcba9876543210", &sealed), None);
    }

    #[test]
    fn the_iv_is_fresh_for_every_frame() {
        let cipher = Cipher::new(*b"0123456789abcdef");
        let a = cipher.seal(b"same frame");
        let b = cipher.seal(b"same frame");
        assert_ne!(a, b);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn a_rotation_reaches_frames_sealed_after_it() {
        let before = Cipher::new(*b"0123456789abcdef");
        let after = Cipher::new(*b"aaaaaaaaaaaaaaaa");
        let old = before.seal(b"before");
        let new = after.seal(b"after");
        assert_eq!(open(b"0123456789abcdef", &old).as_deref(), Some(b"before".as_slice()));
        assert_eq!(open(b"aaaaaaaaaaaaaaaa", &new).as_deref(), Some(b"after".as_slice()));
        // Frames sealed with the old key no longer open with the new one.
        assert_eq!(open(b"aaaaaaaaaaaaaaaa", &old), None);
    }
}
