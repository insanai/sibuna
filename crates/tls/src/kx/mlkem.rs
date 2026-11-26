//! ML-KEM-768 (FIPS 203) as a rustls key exchange group, for the post-quantum half of
//! X25519MLKEM768. The arithmetic is the RustCrypto crate `ml-kem`; the randomness is
//! ring's `SystemRandom`, the source of every other key in the ring provider. The seed, the
//! encapsulated message and the shared secrets are wiped once copied; the decapsulation key
//! wipes itself on drop (`ml-kem`'s `zeroize` feature).

use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{B32, Decapsulate, Key, KeyExport, Seed};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, ProtocolVersion};
use sibuna_crypto::ct::zeroize;

use super::INVALID_KEY_SHARE;

/// The length of an ML-KEM-768 encapsulation key: a client's share.
pub const ENCAPSULATION_KEY_LEN: usize = 1184;

/// The length of an ML-KEM-768 ciphertext: a server's share.
pub const CIPHERTEXT_LEN: usize = 1088;

/// ML-KEM-768 as a key exchange: the client sends an encapsulation key, the server
/// encapsulates a fresh secret to it and sends the ciphertext, and the client decapsulates.
#[derive(Debug)]
pub struct MlKem768;

impl SupportedKxGroup for MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut seed = Seed::default();
        fill(&mut seed)?;
        let decapsulation_key = DecapsulationKey::from_seed(seed);
        zeroize(&mut seed);
        let encapsulation_key = decapsulation_key.encapsulation_key().to_bytes().to_vec();
        Ok(Box::new(Active { decapsulation_key: Box::new(decapsulation_key), encapsulation_key }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let key =
            Key::<EncapsulationKey>::try_from(client_share).map_err(|_| INVALID_KEY_SHARE)?;
        // `new` runs the modulus check of FIPS 203 section 7.2 and refuses a key that fails.
        let encapsulation_key = EncapsulationKey::new(&key).map_err(|_| INVALID_KEY_SHARE)?;
        let mut message = B32::default();
        fill(&mut message)?;
        let (ciphertext, mut secret) = encapsulation_key.encapsulate_deterministic(&message);
        zeroize(&mut message);
        let shared = SharedSecret::from(&secret[..]);
        zeroize(&mut secret);
        Ok(CompletedKeyExchange {
            group: NamedGroup::MLKEM768,
            pub_key: ciphertext.to_vec(),
            secret: shared,
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// A client's started ML-KEM exchange: the decapsulation key and the encoded encapsulation
/// key it sent.
struct Active {
    decapsulation_key: Box<DecapsulationKey>,
    encapsulation_key: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    /// The server's share is the ciphertext; decapsulating it gives the secret. A forged
    /// ciphertext gives a pseudorandom secret (implicit rejection), and the handshake then
    /// fails at the server's Finished message.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let ciphertext = Ciphertext::try_from(peer_pub_key).map_err(|_| INVALID_KEY_SHARE)?;
        let mut secret = self.decapsulation_key.decapsulate(&ciphertext);
        let shared = SharedSecret::from(&secret[..]);
        zeroize(&mut secret);
        Ok(shared)
    }

    fn pub_key(&self) -> &[u8] {
        &self.encapsulation_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }
}

/// Fills `bytes` from the system's random source.
fn fill(bytes: &mut [u8]) -> Result<(), Error> {
    SystemRandom::new().fill(bytes).map_err(|_| Error::FailedToGetRandomBytes)
}
