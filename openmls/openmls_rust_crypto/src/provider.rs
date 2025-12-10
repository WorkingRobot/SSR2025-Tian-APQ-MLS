use std::sync::RwLock;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, KeyInit,
};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::Signer;
//use ed25519_dalek::Signer as _;
//use ed448_goldilocks_plus::Signer as _;
use ed448_goldilocks_plus as ed448_goldilocks;
use hkdf::Hkdf;
use hpke::Hpke;
use hpke_rs_crypto::types as hpke_types;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use ml_dsa::{
    KeyGen, MlDsa44, MlDsa65, MlDsa87,
    SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
    Signature as MlDsaSignature,
    EncodedSigningKey, EncodedVerifyingKey,
    signature::SignatureEncoding,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        self, AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType,
        HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, SignatureScheme,
    },
};
use p256::{
    ecdsa::{signature::Verifier as P256Verifier, Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey},
    EncodedPoint as P256EncodedPoint,
};
use p384::{
    ecdsa::{signature::Verifier as P384Verifier, Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey},
    EncodedPoint as P384EncodedPoint,
};
use p521::{
    ecdsa::{signature::Verifier as P521Verifier, Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey},
    EncodedPoint as P521EncodedPoint,
};
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256, Sha384, Sha512};
//use sha3::Shake256;
use tls_codec::SecretVLBytes;

use crate::hmac;

#[derive(Debug)]
pub struct RustCrypto {
    rng: RwLock<rand_chacha::ChaCha20Rng>,
}

// For testing we want to clone.
// But really we just create a new Rng.
#[cfg(feature = "test-utils")]
impl Clone for RustCrypto {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl Default for RustCrypto {
    fn default() -> Self {
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
        }
    }
}

#[inline(always)]
fn kem_mode(kem: HpkeKemType) -> hpke_types::KemAlgorithm {
    match kem {
        HpkeKemType::DhKemP256 => hpke_types::KemAlgorithm::DhKemP256,
        HpkeKemType::DhKemP384 => hpke_types::KemAlgorithm::DhKemP384,
        HpkeKemType::DhKemP521 => hpke_types::KemAlgorithm::DhKemP521,
        HpkeKemType::DhKem25519 => hpke_types::KemAlgorithm::DhKem25519,
        HpkeKemType::DhKem448 => hpke_types::KemAlgorithm::DhKem448,
        HpkeKemType::XWingKemDraft6 => hpke_types::KemAlgorithm::XWingDraft06,
        HpkeKemType::MlKem512 => hpke_types::KemAlgorithm::MlKem512,
        HpkeKemType::MlKem768 => hpke_types::KemAlgorithm::MlKem768,
        HpkeKemType::MlKem1024 => hpke_types::KemAlgorithm::MlKem1024,
    }
}

#[inline(always)]
fn kdf_mode(kdf: HpkeKdfType) -> hpke_types::KdfAlgorithm {
    match kdf {
        HpkeKdfType::HkdfSha256 => hpke_types::KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => hpke_types::KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => hpke_types::KdfAlgorithm::HkdfSha512,
    }
}

#[inline(always)]
fn aead_mode(aead: HpkeAeadType) -> hpke_types::AeadAlgorithm {
    match aead {
        HpkeAeadType::AesGcm128 => hpke_types::AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => hpke_types::AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => hpke_types::AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => hpke_types::AeadAlgorithm::HpkeExport,
    }
}

impl OpenMlsCrypto for RustCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519,
        ]
    }

    fn hkdf_extract(
        &self,
        hash_type: openmls_traits::types::HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_384 => Ok(Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_512 => Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into()),
        }
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        hmac::hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: openmls_traits::types::HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
            HashType::Sha2_512 => {
                let hkdf = Hkdf::<Sha512>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
            HashType::Sha2_384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(prk)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                let mut okm = vec![0u8; okm_len];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
                Ok(okm.into())
            }
        }
    }

    fn hash(
        &self,
        hash_type: openmls_traits::types::HashType,
        data: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
            HashType::Sha2_384 => Ok(Sha384::digest(data).as_slice().into()),
            HashType::Sha2_512 => Ok(Sha512::digest(data).as_slice().into()),
        }
    }

    fn aead_encrypt(
        &self,
        alg: openmls_traits::types::AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            AeadType::Aes256Gcm => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
        }
    }

    fn aead_decrypt(
        &self,
        alg: openmls_traits::types::AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            AeadType::Aes128Gcm => {
                let aes =
                    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::Aes256Gcm => {
                let aes =
                    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
        }
    }

    fn signature_key_gen(
        &self,
        alg: openmls_traits::types::SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let k = P256SigningKey::random(&mut *rng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                Ok((k.to_bytes().as_slice().into(), pk))
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let k = P384SigningKey::random(&mut *rng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                Ok((k.to_bytes().as_slice().into(), pk))
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let k = P521SigningKey::random(&mut *rng);
                let pk = P521VerifyingKey::from(&k).to_encoded_point(false).as_bytes().into();
                Ok((k.to_bytes().as_slice().into(), pk))
            }
            SignatureScheme::ED25519 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let sk = ed25519_dalek::SigningKey::generate(&mut *rng);
                let pk = sk.verifying_key().to_bytes().into();
                Ok((sk.to_bytes().into(), pk))
            }
            SignatureScheme::ED448 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let sk = ed448_goldilocks::SigningKey::generate(&mut *rng);
                let pk = sk.verifying_key().to_bytes().into();
                Ok((sk.to_bytes().as_slice().into(), pk))
            }
            SignatureScheme::MLDSA44 => {
                let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;
                let kp = MlDsa44::key_gen(&mut *rng);
                let sk_bytes: Vec<u8> = kp.signing_key().encode().to_vec();
                let pk_bytes: Vec<u8> = kp.verifying_key().encode().to_vec();
                Ok((sk_bytes, pk_bytes))
            }
            SignatureScheme::MLDSA65 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let kp = MlDsa65::key_gen(&mut *rng);
                let sk_bytes: Vec<u8> = kp.signing_key().encode().to_vec();
                let pk_bytes: Vec<u8> = kp.verifying_key().encode().to_vec();
                Ok((sk_bytes, pk_bytes))
            }
            SignatureScheme::MLDSA87 => {
                let mut rng = self
                    .rng
                    .write()
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let kp = MlDsa87::key_gen(&mut *rng);
                let sk_bytes: Vec<u8> = kp.signing_key().encode().to_vec();
                let pk_bytes: Vec<u8> = kp.verifying_key().encode().to_vec();
                Ok((sk_bytes, pk_bytes))
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn verify_signature(
        &self,
        alg: openmls_traits::types::SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = P256VerifyingKey::from_encoded_point(
                    &P256EncodedPoint::from_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?,
                )
                .map_err(|_| CryptoError::CryptoLibraryError)?;
                k.verify(
                    data,
                    &P256Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?,
                )
                .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let k = P384VerifyingKey::from_encoded_point(
                    &P384EncodedPoint::from_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?,
                )
                .map_err(|_| CryptoError::CryptoLibraryError)?;
                k.verify(
                    data,
                    &P384Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?,
                )
                .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = P521VerifyingKey::from_encoded_point(
                    &P521EncodedPoint::from_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?,
                )
                .map_err(|_| CryptoError::CryptoLibraryError)?;
                k.verify(
                    data,
                    &P521Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?,
                )
                .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::VerifyingKey::try_from(pk)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                    return Err(CryptoError::CryptoLibraryError);
                }
                let mut sig = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                sig.clone_from_slice(signature);
                k.verify_strict(data, &ed25519_dalek::Signature::from(sig))
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ED448 => {
                use ed448_goldilocks::VerifyingKey;

                // Convert the public key bytes to the correct format
                let public_key_bytes = ed448_goldilocks::PublicKeyBytes(pk.try_into()
                    .map_err(|_| CryptoError::CryptoLibraryError)?);

                // Convert the signature bytes to the correct format
                let sig_bytes = signature.try_into()
                    .map_err(|_| CryptoError::CryptoLibraryError)?;

                // Create the verifying key
                let verifying_key = VerifyingKey::try_from(&public_key_bytes)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;

                // Create the signature
                let sig = ed448_goldilocks::Signature::from_bytes(&sig_bytes)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;

                // Verify the signature
                verifying_key.verify(data, &sig)
                    .map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::MLDSA44 => {
                let pk_enc: EncodedVerifyingKey<MlDsa44> =
                    <EncodedVerifyingKey<MlDsa44> as TryFrom<&[u8]>>::try_from(pk)
                        .map_err(|_| CryptoError::CryptoLibraryError)?;
                let vk: MlDsaVerifyingKey<MlDsa44> = MlDsaVerifyingKey::decode(&pk_enc);

                let sig: MlDsaSignature<MlDsa44> =
                    MlDsaSignature::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;

                vk.verify(data, &sig).map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::MLDSA65 => {
                let pk_enc: EncodedVerifyingKey<MlDsa65> =
                    <EncodedVerifyingKey<MlDsa65> as TryFrom<&[u8]>>::try_from(pk)
                        .map_err(|_| CryptoError::CryptoLibraryError)?;
                let vk: MlDsaVerifyingKey<MlDsa65> = MlDsaVerifyingKey::decode(&pk_enc);

                let sig: MlDsaSignature<MlDsa65> =
                    MlDsaSignature::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;

                vk.verify(data, &sig).map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::MLDSA87 => {
                let pk_enc: EncodedVerifyingKey<MlDsa87> =
                    <EncodedVerifyingKey<MlDsa87> as TryFrom<&[u8]>>::try_from(pk)
                        .map_err(|_| CryptoError::CryptoLibraryError)?;
                let vk: MlDsaVerifyingKey<MlDsa87> = MlDsaVerifyingKey::decode(&pk_enc);

                let sig: MlDsaSignature<MlDsa87> =
                    MlDsaSignature::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;

                vk.verify(data, &sig).map_err(|_| CryptoError::InvalidSignature)
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(
        &self,
        alg: openmls_traits::types::SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, openmls_traits::types::CryptoError> {
        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = P256SigningKey::from_bytes(key.into())
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: P256Signature = k.sign(data);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = P521SigningKey::from_bytes(key.into())
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: P521Signature = k.sign(data);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::try_from(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = k.sign(data);
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ED448 => {
                use ed448_goldilocks::SigningKey;

                let key = SigningKey::try_from(key)
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature = key.sign(data);
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::MLDSA44 => {
                let sk_enc: EncodedSigningKey<MlDsa44> = key.try_into()
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let sk = MlDsaSigningKey::<MlDsa44>::decode(&sk_enc);
                let signature = sk.sign(data);
                Ok(signature.encode().to_vec())
            }
            SignatureScheme::MLDSA65 => {
                let sk_enc: EncodedSigningKey<MlDsa65> = key.try_into()
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let sk = MlDsaSigningKey::<MlDsa65>::decode(&sk_enc);
                let signature = sk.sign(data);
                Ok(signature.encode().to_vec())
            }
            SignatureScheme::MLDSA87 => {
                let sk_enc: EncodedSigningKey<MlDsa87> = key.try_into()
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let sk = MlDsaSigningKey::<MlDsa87>::decode(&sk_enc);
                let signature = sk.sign(data);
                Ok(signature.encode().to_vec())
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<types::HpkeCiphertext, CryptoError> {
        let (kem_output, ciphertext) = hpke_from_config(config)
            .seal(&pk_r.into(), info, aad, ptxt, None, None, None)
            .map_err(|e| match e {
                hpke::HpkeError::InvalidInput => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })?;
        Ok(HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke_from_config(config)
            .open(
                input.kem_output.as_slice(),
                &sk_r.into(),
                info,
                aad,
                input.ciphertext.as_slice(),
                None,
                None,
                None,
            )
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        let (kem_output, context) = hpke_from_config(config)
            .setup_sender(&pk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::SenderSetupError)?;
        let exported_secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok((kem_output, exported_secret.into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let context = hpke_from_config(config)
            .setup_receiver(enc, &sk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::ReceiverSetupError)?;
        let exported_secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok(exported_secret.into())
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<types::HpkeKeyPair, CryptoError> {
        let kp = hpke_from_config(config)
            .derive_key_pair(ikm)
            .map_err(|e| match e {
                hpke::HpkeError::InvalidInput => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })?
            .into_keys();
        Ok(HpkeKeyPair {
            private: kp.0.as_slice().into(),
            public: kp.1.as_slice().into(),
        })
    }
}

fn hpke_from_config(config: HpkeConfig) -> Hpke<HpkeRustCrypto> {
    Hpke::<HpkeRustCrypto>::new(
        hpke::Mode::Base,
        kem_mode(config.0),
        kdf_mode(config.1),
        aead_mode(config.2),
    )
}

impl OpenMlsRand for RustCrypto {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.rng.write().map_err(|_| Self::Error::LockPoisoned)?;
        let mut out = [0u8; N];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.rng.write().map_err(|_| Self::Error::LockPoisoned)?;
        let mut out = vec![0u8; len];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| Self::Error::NotEnoughRandomness)?;
        Ok(out)
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RandError {
    #[error("Rng lock is poisoned.")]
    LockPoisoned,
    #[error("Unable to collect enough randomness.")]
    NotEnoughRandomness,
}
