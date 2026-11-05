//! The RSA key the client announces when it joins.
//!
//! `PlayerChannelHandler` parses it with `KeyFactory.getInstance("RSA")` and an
//! `X509EncodedKeySpec`, so it has to be a real SubjectPublicKeyInfo DER — a
//! placeholder makes the server log "Failed to generate RSA public key" and
//! never send a `ConfigPacket`. With a proxy that encrypts audio the server
//! encrypts the AES key with it (`VoiceTcpServerConnectionManager`); this
//! client does not speak that yet and refuses an encrypted config, but the
//! key itself is genuine either way.

use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// A key pair, generated once per session.
pub struct Identity {
    private: RsaPrivateKey,
    public_der: Vec<u8>,
}

impl Identity {
    /// Generates a fresh 2048-bit key. Takes a moment: do it when the server
    /// hands out its `ConnectionPacket`, not on the game thread's hot path.
    pub fn generate() -> Result<Self, String> {
        let mut rng = rsa::rand_core::OsRng;
        let private =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|error| format!("rsa key: {error}"))?;
        let public = RsaPublicKey::from(&private);
        let public_der = public
            .to_public_key_der()
            .map_err(|error| format!("rsa export: {error}"))?
            .as_bytes()
            .to_vec();

        Ok(Identity {
            private,
            public_der,
        })
    }

    /// What `PlayerInfoPacket.publicKey` carries.
    pub fn public_key(&self) -> &[u8] {
        &self.public_der
    }

    /// Kept for the AES handshake a proxy does; unused until that is ported.
    pub fn private(&self) -> &RsaPrivateKey {
        &self.private
    }
}

/// Checks that a blob is an X.509 RSA key the way the server reads one.
pub fn parses_as_x509(der: &[u8]) -> bool {
    RsaPublicKey::from_public_key_der(der).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_announced_key_is_one_java_can_parse() {
        let identity = Identity::generate().unwrap();
        let der = identity.public_key();

        // A 2048-bit RSA SubjectPublicKeyInfo is around 290 bytes; the packet
        // bound is 1..2048.
        assert!(der.len() > 200 && der.len() < 2048, "{} bytes", der.len());
        assert!(parses_as_x509(der));
    }

    #[test]
    fn junk_is_not_a_key() {
        assert!(!parses_as_x509(&[0u8; 162]));
    }
}
