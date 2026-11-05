//! The AES layer the server insists on.
//!
//! `ConfigPacket.encryption` carries the voice key RSA-encrypted with the
//! public key we announced (`VoiceTcpServerConnectionManager.sendConfigInfo`),
//! and only the **audio payload** of a UDP packet is encrypted: the header,
//! the secret and the timestamp stay in the clear, which is what lets the
//! server forward packets without holding the key open.
//!
//! `AesEncryption` on the Java side is `AES/CBC/PKCS5Padding` with a fresh
//! 16-byte IV written in front of the ciphertext, so a packet's data field is
//! `IV || ciphertext`.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

type Encryptor = cbc::Encryptor<aes::Aes128>;
type Decryptor = cbc::Decryptor<aes::Aes128>;

/// The voice key, after the RSA step.
pub struct Aes {
    key: [u8; 16],
}

impl Aes {
    /// A 16-byte key, as `ServerConfig.voice().aesEncryptionKey()`.
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 16 {
            return Err(format!("the voice key is {} bytes, not 16", key.len()));
        }
        let mut fixed = [0u8; 16];
        fixed.copy_from_slice(key);
        Ok(Aes { key: fixed })
    }

    /// `IV || AES/CBC/PKCS5Padding(data)`.
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; 16];
        fill_random(&mut iv);
        let cipher = Encryptor::new(&self.key.into(), &iv.into());
        let mut out = iv.to_vec();
        out.extend_from_slice(&cipher.encrypt_padded_vec_mut::<Pkcs7>(data));
        out
    }

    /// The other direction. `None` for anything that is not a whole block with
    /// a valid pad: a stray datagram must not take the session down.
    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 32 || data.len() % 16 != 0 {
            return None;
        }
        let (iv, body) = data.split_at(16);
        let cipher = Decryptor::new(&self.key.into(), iv.into());
        cipher.decrypt_padded_vec_mut::<Pkcs7>(body).ok()
    }
}

/// `Cipher.getInstance("RSA")` on the Java side is PKCS#1 v1.5.
pub fn unwrap_key(private: &RsaPrivateKey, blob: &[u8]) -> Result<Vec<u8>, String> {
    private
        .decrypt(Pkcs1v15Encrypt, blob)
        .map_err(|error| format!("rsa: {error}"))
}

/// A private key from the DER we keep between sessions.
pub fn private_from_der(der: &[u8]) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_der(der).map_err(|error| format!("rsa key: {error}"))
}

fn fill_random(out: &mut [u8]) {
    use rsa::rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::Pkcs1v15Encrypt as Enc;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPublicKey;

    #[test]
    fn aes_round_trips_and_hides_the_payload() {
        let aes = Aes::new(b"0123456789abcdef").unwrap();
        let plain = b"an opus frame".to_vec();
        let sealed = aes.encrypt(&plain);

        assert_ne!(&sealed[16..], plain.as_slice());
        assert_eq!(sealed.len() % 16, 0, "IV plus whole blocks");
        assert_eq!(aes.decrypt(&sealed).unwrap(), plain);
    }

    #[test]
    fn two_packets_with_the_same_data_differ() {
        let aes = Aes::new(b"0123456789abcdef").unwrap();
        let a = aes.encrypt(b"same");
        let b = aes.encrypt(b"same");
        assert_ne!(a, b, "the IV is fresh each time");
    }

    #[test]
    fn a_short_key_is_refused() {
        assert!(Aes::new(b"short").is_err());
    }

    #[test]
    fn the_config_blob_is_rsa_pkcs1v15() {
        let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        let blob = public.encrypt(&mut rsa::rand_core::OsRng, Enc, b"0123456789abcdef").unwrap();

        assert_eq!(unwrap_key(&private, &blob).unwrap(), b"0123456789abcdef");

        let der = private.to_pkcs8_der().unwrap();
        let again = private_from_der(der.as_bytes()).unwrap();
        assert_eq!(unwrap_key(&again, &blob).unwrap(), b"0123456789abcdef");
    }
}
