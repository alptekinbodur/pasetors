#![cfg_attr(docsrs, doc(cfg(feature = "v4")))]

use core::convert::TryFrom;
use core::marker::PhantomData;

use crate::common::{encode_b64, validate_footer_untrusted_token};
use crate::errors::Error;
use crate::keys::{
    AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate, SymmetricKey,
};
use crate::pae;
use crate::token::{Local, Public, TrustedToken, UntrustedToken};
use crate::version::private::Version;
use alloc::string::String;
use alloc::vec::Vec;
use blake2b::SecretKey as AuthKey;
use ed25519_compact::{KeyPair, PublicKey, SecretKey, Seed, Signature};
use orion::hazardous::mac::blake2b;
use orion::hazardous::mac::blake2b::Blake2b;
use orion::hazardous::stream::xchacha20;
use subtle::ConstantTimeEq;
use xchacha20::Nonce as EncNonce;
use xchacha20::SecretKey as EncKey;

#[derive(Debug, PartialEq, Eq, Clone)]
/// Version 4 of the PASETO spec.
pub struct V4;

impl Version for V4 {
    const LOCAL_KEY: usize = 32;
    const SECRET_KEY: usize = 32 + Self::PUBLIC_KEY; // Seed || PK
    const PUBLIC_KEY: usize = 32;
    const PUBLIC_SIG: usize = 64;
    const LOCAL_NONCE: usize = 32;
    const LOCAL_TAG: usize = 32;
    const PUBLIC_HEADER: &'static str = "v4.public.";
    const LOCAL_HEADER: &'static str = "v4.local.";
    #[cfg(feature = "paserk")]
    const PASERK_ID: usize = 44;

    fn validate_local_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::LOCAL_KEY {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::SECRET_KEY {
            return Err(Error::Key);
        }

        let seed = Seed::from_slice(&key_bytes[..32]).map_err(|_| Error::Key)?;
        let kp = KeyPair::from_seed(seed);

        if !bool::from(kp.pk.as_slice().ct_eq(&key_bytes[32..])) {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::PUBLIC_KEY {
            return Err(Error::Key);
        }

        Ok(())
    }
}

impl TryFrom<&AsymmetricSecretKey<V4>> for AsymmetricPublicKey<V4> {
    type Error = Error;

    fn try_from(value: &AsymmetricSecretKey<V4>) -> Result<Self, Self::Error> {
        AsymmetricPublicKey::<V4>::from(&value.as_bytes()[32..])
    }
}

impl Generate<AsymmetricKeyPair<V4>, V4> for AsymmetricKeyPair<V4> {
    fn generate() -> Result<AsymmetricKeyPair<V4>, Error> {
        let key_pair = KeyPair::generate();

        let secret = AsymmetricSecretKey::<V4>::from(key_pair.sk.as_ref())
            .map_err(|_| Error::KeyGeneration)?;
        let public = AsymmetricPublicKey::<V4>::from(key_pair.pk.as_ref())
            .map_err(|_| Error::KeyGeneration)?;

        Ok(Self { public, secret })
    }
}

impl Generate<SymmetricKey<V4>, V4> for SymmetricKey<V4> {
    fn generate() -> Result<SymmetricKey<V4>, Error> {
        let mut rng_bytes = vec![0u8; V4::LOCAL_KEY];
        V4::validate_local_key(&rng_bytes)?;
        getrandom::fill(&mut rng_bytes)?;

        Ok(Self {
            bytes: rng_bytes,
            phantom: PhantomData,
        })
    }
}

/// PASETO v4 public tokens.
pub struct PublicToken;

impl PublicToken {
    /// The header and purpose for the public token: `v4.public.`.
    pub const HEADER: &'static str = "v4.public.";

    /// Create a public token.
    pub fn sign(
        secret_key: &AsymmetricSecretKey<V4>,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let sk = SecretKey::from_slice(secret_key.as_bytes()).map_err(|_| Error::Key)?;

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);
        let m2 = pae::pae(&[Self::HEADER.as_bytes(), message, f, i])?;
        let sig = sk.sign(m2, None);

        let mut m_sig: Vec<u8> = Vec::from(message);
        m_sig.extend_from_slice(sig.as_ref());

        let token_no_footer = format!("{}{}", Self::HEADER, encode_b64(m_sig)?);

        if f.is_empty() {
            Ok(token_no_footer)
        } else {
            Ok(format!("{}.{}", token_no_footer, encode_b64(f)?))
        }
    }

    /// Verify a public token.
    ///
    /// If `footer.is_none()`, then it will be validated but not compared to a known value.
    /// If `footer.is_some()`, then it will be validated AND compared to the known value.
    pub fn verify(
        public_key: &AsymmetricPublicKey<V4>,
        token: &UntrustedToken<Public, V4>,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        validate_footer_untrusted_token(token, footer)?;

        let f = token.untrusted_footer();
        let i = implicit_assert.unwrap_or(&[]);
        let sm = token.untrusted_message();
        let m = token.untrusted_payload();
        let s = sm[m.len()..m.len() + V4::PUBLIC_SIG].as_ref();

        let m2 = pae::pae(&[Self::HEADER.as_bytes(), m, f, i])?;
        let pk: PublicKey = PublicKey::from_slice(public_key.as_bytes()).map_err(|_| Error::Key)?;

        debug_assert!(s.len() == V4::PUBLIC_SIG);
        // If the below fails, it is an invalid signature.
        let sig = Signature::from_slice(s).map_err(|_| Error::TokenValidation)?;

        if pk.verify(m2, &sig).is_ok() {
            TrustedToken::_new(Self::HEADER, m, f, i)
        } else {
            Err(Error::TokenValidation)
        }
    }
}

/// PASETO v4 local tokens.
pub struct LocalToken;

impl LocalToken {
    /// The header and purpose for the local token: `v4.local.`.
    pub const HEADER: &'static str = "v4.local.";

    /// Domain separator for key-splitting the encryption key (21 in length as bytes).
    const DOMAIN_SEPARATOR_ENC: &'static str = "paseto-encryption-key";

    /// Domain separator for key-splitting the authentication key (24 in length as bytes).
    const DOMAIN_SEPARATOR_AUTH: &'static str = "paseto-auth-key-for-aead";

    const M1_LEN: usize = V4::LOCAL_NONCE + Self::DOMAIN_SEPARATOR_ENC.len();
    const M2_LEN: usize = V4::LOCAL_NONCE + Self::DOMAIN_SEPARATOR_AUTH.len();

    /// Split the user-provided secret key into keys used for encryption and authentication.
    fn key_split(sk: &[u8], n: &[u8]) -> Result<(EncKey, EncNonce, AuthKey), Error> {
        debug_assert_eq!(n.len(), V4::LOCAL_NONCE);
        debug_assert_eq!(sk.len(), V4::LOCAL_KEY);

        let mut m1 = [0u8; Self::M1_LEN];
        m1[..21].copy_from_slice(Self::DOMAIN_SEPARATOR_ENC.as_bytes());
        m1[21..].copy_from_slice(n);

        let mut m2 = [0u8; Self::M2_LEN];
        m2[..24].copy_from_slice(Self::DOMAIN_SEPARATOR_AUTH.as_bytes());
        m2[24..].copy_from_slice(n);

        let sk = blake2b::SecretKey::from_slice(sk).unwrap();
        let mut b2_ctx = Blake2b::new(&sk, 56).unwrap();
        b2_ctx.update(&m1).unwrap();
        let tmp = b2_ctx.finalize().unwrap();
        let enc_key = EncKey::from_slice(&tmp.unprotected_as_bytes()[..32]).unwrap();
        let n2 = EncNonce::from_slice(&tmp.unprotected_as_bytes()[32..]).unwrap();

        b2_ctx = Blake2b::new(&sk, V4::LOCAL_TAG).unwrap();
        b2_ctx.update(&m2).unwrap();
        let auth_key =
            AuthKey::from_slice(b2_ctx.finalize().unwrap().unprotected_as_bytes()).unwrap();

        Ok((enc_key, n2, auth_key))
    }

    /// Encrypt and authenticate a message using nonce directly.
    pub(crate) fn encrypt_with_nonce(
        secret_key: &SymmetricKey<V4>,
        nonce: &[u8],
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        debug_assert_eq!(nonce.len(), V4::LOCAL_NONCE);
        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);

        let (enc_key, n2, auth_key) = Self::key_split(secret_key.as_bytes(), nonce)?;

        let mut ciphertext = vec![0u8; message.len()];
        xchacha20::encrypt(&enc_key, &n2, 0, message, &mut ciphertext)
            .map_err(|_| Error::Encryption)?;
        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), nonce, ciphertext.as_slice(), f, i])?;

        let mut b2_ctx = Blake2b::new(&auth_key, V4::LOCAL_TAG).unwrap();
        b2_ctx
            .update(pre_auth.as_slice())
            .map_err(|_| Error::Encryption)?;
        let tag = b2_ctx.finalize().map_err(|_| Error::Encryption)?;

        // nonce and tag lengths are both 32, so obviously safe to op::add
        let concat_len: usize = match (nonce.len() + tag.len()).checked_add(ciphertext.len()) {
            Some(len) => len,
            None => return Err(Error::Encryption),
        };
        let mut concat = vec![0u8; concat_len];
        concat[..32].copy_from_slice(nonce);
        concat[32..32 + ciphertext.len()].copy_from_slice(ciphertext.as_slice());
        concat[concat_len - V4::LOCAL_TAG..].copy_from_slice(tag.unprotected_as_bytes());

        let token_no_footer = format!("{}{}", Self::HEADER, encode_b64(concat)?);

        if f.is_empty() {
            Ok(token_no_footer)
        } else {
            Ok(format!("{}.{}", token_no_footer, encode_b64(f)?))
        }
    }

    /// Create a local token.
    pub fn encrypt(
        secret_key: &SymmetricKey<V4>,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let mut n = [0u8; V4::LOCAL_NONCE];
        getrandom::fill(&mut n)?;

        Self::encrypt_with_nonce(secret_key, &n, message, footer, implicit_assert)
    }

    #[allow(clippy::many_single_char_names)] // The single-char names match those in the spec
    /// Verify and decrypt a local token.
    ///
    /// If `footer.is_none()`, then it will be validated but not compared to a known value.
    /// If `footer.is_some()`, then it will be validated AND compared to the known value.
    pub fn decrypt(
        secret_key: &SymmetricKey<V4>,
        token: &UntrustedToken<Local, V4>,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        validate_footer_untrusted_token(token, footer)?;

        let f = token.untrusted_footer();
        let i = implicit_assert.unwrap_or(&[]);
        let nc = token.untrusted_message();

        let mut n: [u8; 32] = [0u8; V4::LOCAL_NONCE];
        n.copy_from_slice(nc[..V4::LOCAL_NONCE].as_ref());
        let c = token.untrusted_payload();
        let t = nc[nc.len() - V4::LOCAL_TAG..].as_ref();

        let (enc_key, n2, auth_key) = Self::key_split(secret_key.as_bytes(), &n)?;

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), n.as_ref(), c, f, i])?;
        let expected_tag = blake2b::Tag::from_slice(t).map_err(|_| Error::TokenValidation)?;
        Blake2b::verify(&expected_tag, &auth_key, 32, pre_auth.as_slice())
            .map_err(|_| Error::TokenValidation)?;

        let mut out = vec![0u8; c.len()];
        xchacha20::decrypt(&enc_key, &n2, 0, c, &mut out).map_err(|_| Error::TokenValidation)?;

        TrustedToken::_new(Self::HEADER, &out, f, i)
    }
}

