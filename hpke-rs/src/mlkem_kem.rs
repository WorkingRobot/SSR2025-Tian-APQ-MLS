//! Handler for passing data between RustCrypto ML-KEM and kem.rs

use alloc::vec::Vec;
use hpke_rs_crypto::{error::Error, types::KemAlgorithm, HpkeCrypto};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use rand::Rng;
use crate::kem::{PrivateKey, PublicKey};
use hybrid_array::{Array, typenum::Unsigned};

// Correct imports based on the module structure
use ml_kem::{
    kem::{Encapsulate, Decapsulate},
    EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768,
    Ciphertext, SharedKey                  // Core KEM trait
};


/// Helper function to create a seeded RNG from the input key material (IKM)
fn create_rng_from_ikm(ikm: &[u8]) -> Result<ChaChaRng, Error> {
    if ikm.len() < 32 {
        return Err(Error::CryptoLibraryError(
            "IKM must be at least 32 bytes long".into()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&ikm[0..32]);
    Ok(ChaChaRng::from_seed(seed))
}

/// Encapsulation function
pub(super) fn encaps<Crypto: HpkeCrypto>(
    alg: KemAlgorithm,
    pk_r: &[u8],
    _suite_id: &[u8],
    ikm: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut rng = create_rng_from_ikm(ikm)?;

    match alg {
        KemAlgorithm::MlKem512 => {
            // Get the concrete types for ML-KEM 512
            type EncapKey512 = <MlKem512 as KemCore>::EncapsulationKey;

            // Check the public key size
            let key_bytes: &[u8; <EncapKey512 as EncodedSizeUser>::EncodedSize::USIZE] =
                pk_r.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid public key size for ML-KEM 512".into())
                })?;

            let public_key = EncapKey512::from_bytes(key_bytes.into());

            // Perform encapsulation
            let (ciphertext, shared_secret) = public_key.encapsulate(&mut rng).map_err(|_| {
                Error::CryptoLibraryError("ML-KEM 512 encapsulation failed".into())
            })?;
            // Convert results to byte vectors
            let shared_secret_bytes= shared_secret.as_slice().to_vec();
            let ciphertext_bytes = ciphertext.as_slice().to_vec();

            Ok((shared_secret_bytes, ciphertext_bytes))
        }

        KemAlgorithm::MlKem768 => {
            type EncapKey768 = <MlKem768 as KemCore>::EncapsulationKey;

            let key_bytes: &[u8; <EncapKey768 as EncodedSizeUser>::EncodedSize::USIZE] =
                pk_r.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid public key size for ML-KEM 768".into())
                })?;

            let public_key = EncapKey768::from_bytes(key_bytes.into()) ;

            let (ciphertext, shared_secret) = public_key.encapsulate(&mut rng).map_err(|_| {
                Error::CryptoLibraryError("ML-KEM 768 encapsulation failed".into())
            })?;

            let shared_secret_bytes = shared_secret.as_slice().to_vec();
            let ciphertext_bytes = ciphertext.as_slice().to_vec();

            Ok((shared_secret_bytes, ciphertext_bytes))
        }

        KemAlgorithm::MlKem1024 => {
            type EncapKey1024 = <MlKem1024 as KemCore>::EncapsulationKey;

            let key_bytes: &[u8; <EncapKey1024 as EncodedSizeUser>::EncodedSize::USIZE] =
                pk_r.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid public key size for ML-KEM 1024".into())
                })?;

            let public_key = EncapKey1024::from_bytes(key_bytes.into());

            let (ciphertext, shared_secret) = public_key.encapsulate(&mut rng).map_err(|_| {
                Error::CryptoLibraryError("ML-KEM 1024 encapsulation failed".into())
            })?;

            let shared_secret_bytes = shared_secret.as_slice().to_vec();
            let ciphertext_bytes = ciphertext.as_slice().to_vec();

            Ok((shared_secret_bytes, ciphertext_bytes))
        }

        _ => Err(Error::CryptoLibraryError("Unsupported KEM algorithm".into())),
    }
}

pub(super) fn decaps<Crypto: HpkeCrypto>(
    alg: KemAlgorithm,
    enc: &[u8],
    sk_r: &[u8],
    _suite_id: &[u8],
) -> Result<Vec<u8>, Error> {
    match alg {
        KemAlgorithm::MlKem512 => {
            type DecapKey512 = <MlKem512 as KemCore>::DecapsulationKey;
            // type Ciphertext512 = <MlKem512 as KemCore>::Ciphertext;

            // Convert private key bytes
            let key_bytes: &[u8; <DecapKey512 as EncodedSizeUser>::EncodedSize::USIZE] =
                sk_r.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid private key size for ML-KEM 512".into())
                })?;

            // Convert ciphertext bytes
            let ct_bytes: &[u8; <MlKem512 as KemCore>::CiphertextSize::USIZE] =
                enc.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid ciphertext size for ML-KEM 512".into())
                })?;


            // Deserialize private key
            let private_key = DecapKey512::from_bytes(key_bytes.into());

            // Perform decapsulation
            let shared_secret = private_key.decapsulate(ct_bytes.into()).map_err(|_| {
                Error::CryptoLibraryError("ML-KEM 512 decapsulation failed".into())
            })?;

            Ok(shared_secret.as_slice().to_vec())
        }

        KemAlgorithm::MlKem768 => {
            type DecapKey768 = <MlKem768 as KemCore>::DecapsulationKey;
            // type Ciphertext768 = <MlKem768 as KemCore>::Ciphertext;

            // Convert private key bytes
            let key_bytes: &[u8; <DecapKey768 as EncodedSizeUser>::EncodedSize::USIZE] =
                sk_r.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid private key size for ML-KEM 768".into())
                })?;

            // Convert ciphertext bytes
            let ct_bytes: &[u8; <MlKem768 as KemCore>::CiphertextSize::USIZE] =
                enc.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid ciphertext size for ML-KEM 768".into())
                })?;


            // Deserialize private key
            let private_key = DecapKey768::from_bytes(key_bytes.into());

            // Perform decapsulation
            let shared_secret = private_key.decapsulate(ct_bytes.into()).map_err(|_| {
                Error::CryptoLibraryError("ML-KEM 768 decapsulation failed".into())
            })?;

            Ok(shared_secret.as_slice().to_vec())
        }

        KemAlgorithm::MlKem1024 => {
            type DecapKey1024 = <MlKem1024 as KemCore>::DecapsulationKey;
            // type Ciphertext1024 = <MlKem1024 as KemCore>::Ciphertext;

            // Convert private key bytes
            let key_bytes: &[u8; <DecapKey1024 as EncodedSizeUser>::EncodedSize::USIZE] =
                sk_r.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid private key size for ML-KEM 1024".into())
                })?;

            // Convert ciphertext bytes
            let ct_bytes: &[u8; <MlKem1024 as KemCore>::CiphertextSize::USIZE] =
                enc.try_into().map_err(|_| {
                    Error::CryptoLibraryError("Invalid ciphertext size for ML-KEM 1024".into())
                })?;


            // Deserialize private key
            let private_key = DecapKey1024::from_bytes(key_bytes.into());

            // Perform decapsulation
            let shared_secret = private_key.decapsulate(ct_bytes.into()).map_err(|_| {
                Error::CryptoLibraryError("ML-KEM 1024 decapsulation failed".into())
            })?;

            Ok(shared_secret.as_slice().to_vec())
        }

        _ => Err(Error::CryptoLibraryError("Unsupported KEM algorithm".into())),
    }
}

// pub (super) fn derive_key_pair<Crypto: HpkeCrypto>(
//     alg: KemAlgorithm,
//     _suite_id: &[u8],
//     ikm: &[u8],
// ) ->Result<(PublicKey, PrivateKey), Error>{
//     let (public_key_bytes, private_key_bytes) = match alg {
//         KemAlgorithm::MlKem512 => derive_key_pair512::<Crypto>(alg, _suite_id, ikm)?,
//         KemAlgorithm::MlKem768 => derive_key_pair768(alg, _suite_id, ikm)?,
//         KemAlgorithm::MlKem1024 => derive_key_pair1024(alg, _suite_id, ikm)?,
//         _ => {
//             panic!("This should be unreachable. Only ML-KEM algorithms are implemented.")
//         }
//     };
//     Ok((public_key_bytes, private_key_bytes))
// }

/// Derive key pair for ML-KEM 512
pub(super) fn derive_key_pair512<Crypto: HpkeCrypto>(
    _alg: KemAlgorithm,
    _suite_id: &[u8],
    ikm: &[u8],
) -> Result<(PublicKey, PrivateKey), Error> {
    let mut rng = create_rng_from_ikm(ikm)?;
    let (private_key, public_key) = MlKem512::generate(&mut rng);

    let private_key_bytes = private_key.as_bytes().to_vec();
    let public_key_bytes = public_key.as_bytes().to_vec();

    Ok((public_key_bytes, private_key_bytes))
}

/// Derive key pair for ML-KEM 768
pub(super) fn derive_key_pair768<Crypto: HpkeCrypto>(
    _alg: KemAlgorithm,
    _suite_id: &[u8],
    ikm: &[u8],
) -> Result<(PublicKey, PrivateKey), Error> {
    let mut rng = create_rng_from_ikm(ikm)?;
    let (private_key, public_key) = MlKem768::generate(&mut rng);

    let private_key_bytes = private_key.as_bytes().to_vec();
    let public_key_bytes = public_key.as_bytes().to_vec();

    Ok((public_key_bytes, private_key_bytes))
}

/// Derive key pair for ML-KEM 1024
pub(super) fn derive_key_pair1024<Crypto: HpkeCrypto>(
    _alg: KemAlgorithm,
    _suite_id: &[u8],
    ikm: &[u8],
) -> Result<(PublicKey, PrivateKey), Error> {
    let mut rng = create_rng_from_ikm(ikm)?;
    let (private_key, public_key) = MlKem1024::generate(&mut rng);

    let private_key_bytes = private_key.as_bytes().to_vec();
    let public_key_bytes = public_key.as_bytes().to_vec();

    Ok((public_key_bytes, private_key_bytes))
}
