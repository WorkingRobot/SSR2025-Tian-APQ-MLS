//! # Basic Credential
//!
//! An implementation of the basic credential from the MLS spec.
//!
//! For now this credential uses only RustCrypto.

use std::fmt::Debug;

use openmls_traits::{
    signatures::{Signer, SignerError},
    storage::{self, StorageProvider, CURRENT_VERSION},
    types::{CryptoError, SignatureScheme},
};

use p256::ecdsa::{signature::Signer as P256Signer, Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use p521::ecdsa::{Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey};
use ed448_goldilocks_plus as ed448_goldilocks;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

/// A signature key pair for the basic credential.
///
/// This can be used as keys to implement the MLS basic credential. It is a simple
/// private and public key pair with corresponding signature scheme.
#[derive(
    TlsSerialize, TlsSize, TlsDeserialize, TlsDeserializeBytes, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "clonable", derive(Clone))]
pub struct SignatureKeyPair {
    private: Vec<u8>,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

impl Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &"***".to_string())
            .field("public", &self.public)
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}

impl Signer for SignatureKeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        match self.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = P256SigningKey::from_bytes(self.private.as_slice().into())
                    .map_err(|_| SignerError::SigningError)?;
                let signature: P256Signature = k.sign(payload);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let k = P384SigningKey::from_bytes(self.private.as_slice().into())
                    .map_err(|_| SignerError::SigningError)?;
                let signature: P384Signature = k.sign(payload);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = P521SigningKey::from_bytes(self.private.as_slice().into())
                    .map_err(|_| SignerError::SigningError)?;
                let signature: P521Signature = k.sign(payload);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::try_from(self.private.as_slice())
                    .map_err(|_| SignerError::SigningError)?;
                let signature = k.sign(payload);
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ED448 => {
                use ed448_goldilocks::{SigningKey};
                let k = SigningKey::try_from(&self.private)
                    .map_err(|_| SignerError::SigningError)?;
                let signature = k.sign(payload);
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::MLDSA44 => {
                use ml_dsa::{MlDsa44, EncodedSigningKey, SigningKey, signature::SignatureEncoding};
                let k: &EncodedSigningKey<MlDsa44> = self.private().try_into()
                    .map_err(|_| SignerError::SigningError)?;
                let k = SigningKey::<MlDsa44>::decode(k);
                let signature = k.sign(payload);
                Ok(signature.to_bytes().to_vec())
            }
            SignatureScheme::MLDSA65 => {
                use ml_dsa::{MlDsa65, EncodedSigningKey, SigningKey, signature::SignatureEncoding};
                let k: &EncodedSigningKey<MlDsa65> = self.private().try_into()
                    .map_err(|_| SignerError::SigningError)?;
                let k = SigningKey::<MlDsa65>::decode(k);
                let signature = k.sign(payload);
                Ok(signature.to_bytes().to_vec())
            }
            SignatureScheme::MLDSA87 => {
                use ml_dsa::{MlDsa87, EncodedSigningKey, SigningKey, signature::SignatureEncoding};
                let k: &EncodedSigningKey<MlDsa87> = self.private().try_into()
                    .map_err(|_| SignerError::SigningError)?;
                let k = SigningKey::<MlDsa87>::decode(k);
                let signature = k.sign(payload);
                Ok(signature.to_bytes().to_vec())
            }
            _ => Err(SignerError::SigningError),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

/// Compute the ID for a [`Signature`] in the key store.
fn id(public_key: &[u8], signature_scheme: SignatureScheme) -> Vec<u8> {
    const LABEL: &[u8; 22] = b"RustCryptoSignatureKey";
    let mut id = public_key.to_vec();
    id.extend_from_slice(LABEL);
    let signature_scheme = (signature_scheme as u16).to_be_bytes();
    id.extend_from_slice(&signature_scheme);
    id
}

impl SignatureKeyPair {
    /// Generates a fresh signature keypair using the [`SignatureScheme`].
    pub fn new(signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        let (private, public) = match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = P256SigningKey::random(&mut OsRng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                (k.to_bytes().as_slice().into(), pk)
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let k = P384SigningKey::random(&mut OsRng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                (k.to_bytes().as_slice().into(), pk)
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = P521SigningKey::random(&mut OsRng);
                let pk = P521VerifyingKey::from(&k).to_encoded_point(false).as_bytes().into();
                (k.to_bytes().as_slice().into(), pk)
            }
            SignatureScheme::ED25519 => {
                let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let pk = sk.verifying_key().to_bytes().into();
                (sk.to_bytes().into(), pk)
            }
            SignatureScheme::ED448 => {
                use ed448_goldilocks::SigningKey;
                let k = SigningKey::generate(&mut OsRng);
                let pk = k.verifying_key().to_bytes().into();
                (k.to_bytes().as_slice().into(), pk)
            }
            SignatureScheme::MLDSA44 => {
                use ml_dsa::{MlDsa44, KeyGen};
                let kp = MlDsa44::key_gen(&mut OsRng);
                let sk = kp.signing_key().encode();
                let pk = kp.verifying_key().encode();
                (sk.to_vec(), pk.to_vec())
            }
            SignatureScheme::MLDSA65 => {
                use ml_dsa::{MlDsa65, KeyGen};
                let kp = MlDsa65::key_gen(&mut OsRng);
                let sk = kp.signing_key().encode();
                let pk = kp.verifying_key().encode();
                (sk.to_vec(), pk.to_vec())
            }
            SignatureScheme::MLDSA87 => {
                use ml_dsa::{MlDsa87, KeyGen};
                let kp = MlDsa87::key_gen(&mut OsRng);
                let sk = kp.signing_key().encode();
                let pk = kp.verifying_key().encode();
                (sk.to_vec(), pk.to_vec())
            }
            _ => return Err(CryptoError::UnsupportedSignatureScheme),
        };

        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }

    /// Create a new signature key pair from the raw keys.
    pub fn from_raw(signature_scheme: SignatureScheme, private: Vec<u8>, public: Vec<u8>) -> Self {
        Self {
            private,
            public,
            signature_scheme,
        }
    }

    pub fn id(&self) -> StorageId {
        StorageId {
            value: id(&self.public, self.signature_scheme),
        }
    }

    /// Store this signature key pair in the key store.
    pub fn store<T>(&self, store: &T) -> Result<(), T::Error>
    where
        T: StorageProvider<CURRENT_VERSION>,
    {
        store.write_signature_key_pair(&self.id(), self)
    }

    /// Read a signature key pair from the key store.
    pub fn read(
        store: &impl StorageProvider<CURRENT_VERSION>,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Option<Self> {
        store
            .signature_key_pair(&StorageId {
                value: id(public_key, signature_scheme),
            })
            .ok()
            .flatten()
    }

    /// Delete a signature key pair from the key store.
    pub fn delete<T: StorageProvider<CURRENT_VERSION>>(
        store: &T,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Result<(), T::Error> {
        let id = StorageId {
            value: id(public_key, signature_scheme),
        };
        store.delete_signature_key_pair(&id)
    }

    /// Get the public key as byte slice.
    pub fn public(&self) -> &[u8] {
        self.public.as_ref()
    }

    /// Get the public key as byte vector.
    pub fn to_public_vec(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Get the [`SignatureScheme`] of this signature key.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    #[cfg(feature = "test-utils")]
    pub fn private(&self) -> &[u8] {
        &self.private
    }
}

// Storage

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageId {
    value: Vec<u8>,
}

impl From<Vec<u8>> for StorageId {
    fn from(vec: Vec<u8>) -> Self {
        StorageId { value: vec }
    }
}

// Implement key traits for the storage id
impl storage::Key<CURRENT_VERSION> for StorageId {}
impl storage::traits::SignaturePublicKey<CURRENT_VERSION> for StorageId {}

// Implement entity trait for the signature key pair
impl storage::Entity<CURRENT_VERSION> for SignatureKeyPair {}
impl storage::traits::SignatureKeyPair<CURRENT_VERSION> for SignatureKeyPair {}
