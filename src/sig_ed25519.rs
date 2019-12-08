use crate::util::log;
use ed25519_dalek::{verify_batch as dalek_verify_batch, ExpandedSecretKey, PublicKey, SecretKey, Signature};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

// Should i make it u8 to save bytes? Don't know if the compiler can take care of that. Should check.
const PUBLIC_KEY_LENGTH: usize = 32;
const SECRET_KEY_LENGTH: usize = 32;
// Expanded secret key length
const EXP_SECRET_LENGTH: usize = 64;
// Signature length
const SIG_LENGTH: usize = 64;
// Pre-hashed message length
const PH_MSG_LENGTH: usize = 64;
// Context length
const CTX_LENGTH: usize = 255;

use sha2::digest::generic_array::typenum::{U128, U28, U32, U48, U64};
use sha2::digest::generic_array::{ArrayLength, GenericArray};
use sha2::Digest;
use serde_json::Error;

/// Sha512Output is initialized with the prehashed message.
/// The Digest trait it implemented because Dalek's `sign_prehashed` method expects the prehashed
/// message of that type so it can all the `result` method. Therefore only the result method is
/// implemented, rest are unimplemented as they won't be called.
struct Sha512Output {
    pub h: GenericArray<u8, U64>,
}
impl Digest for Sha512Output {
    type OutputSize = U64;

    fn new() -> Self {
        unimplemented!()
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        unimplemented!()
    }

    fn chain<B: AsRef<[u8]>>(self, data: B) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.h
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }

    fn reset(&mut self) {
        unimplemented!()
    }

    fn output_size() -> usize {
        unimplemented!()
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }
}

macro_rules! create_obj_from_Uint8Array {
    ($key:ident, $expected_key_length :ident, $key_type: ident, $err_code_1: expr, $err_code_2: expr) => {{
        if $key.length() != $expected_key_length as u32 {
            log(&format!("Error code while creating object {}", $err_code_1));
            return $err_code_1;
        }
        let mut key_bytes: [u8; $expected_key_length] = [0; $expected_key_length];
        $key.copy_to(&mut key_bytes);
        let k = $key_type::from_bytes(&key_bytes);
        if k.is_err() {
            log(&format!("Error code while creating object {}", $err_code_2));
            return $err_code_2;
        }
        k.unwrap()
    }};
}

/// Create a new keypair which will be used for ed25519 signing and verification.
/// On success, returns 0
#[wasm_bindgen]
pub fn new_sig_keypair(secret_key: &mut [u8], public_key: &mut [u8]) -> i8 {
    log("Got new keygen request for signing");
    log(&format!("sk len is {}", secret_key.len()));
    log(&format!("pk len is {}", public_key.len()));
    if secret_key.len() != SECRET_KEY_LENGTH {
        return -1;
    }
    if public_key.len() != PUBLIC_KEY_LENGTH {
        return -2;
    }
    let mut rng = rand_06::thread_rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = PublicKey::from(&sk);
    // sk and pk will be dropped when the function exits
    secret_key.clone_from_slice(&sk.to_bytes());
    public_key.clone_from_slice(pk.as_bytes());
    0
}

/// Takes a secret key, converts to to an expanded secret key (`ExpandedSecretKey`).
/// The expanded secret key is the result of some manipulations done on the hashed secret key.
/// Only expanded secret key can be used to sign messages.
/// On success, returns 0
#[wasm_bindgen]
pub fn sign_with_secret_key(
    secret_key: Uint8Array,
    public_key: Uint8Array,
    message: Uint8Array,
    signature: &mut [u8],
) -> i8 {
    log("Got new request for signing");
    log(&format!("sk len is {}", secret_key.length()));
    log(&format!("pk len is {}", public_key.length()));

    let sk = create_obj_from_Uint8Array!(secret_key, SECRET_KEY_LENGTH, SecretKey, -1, -2);

    let pk = create_obj_from_Uint8Array!(public_key, PUBLIC_KEY_LENGTH, PublicKey, -3, -4);

    if signature.len() != SIG_LENGTH {
        return -5;
    }

    let exp_sk = ExpandedSecretKey::from(&sk);
    let msg = message.to_vec();
    let sig = exp_sk.sign(&msg, &pk);
    signature.clone_from_slice(&sig.to_bytes());
    0
}

/// Verify a signature. Returns 0 on successful verification
#[wasm_bindgen]
pub fn verify(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array) -> i8 {
    log("Got new request for verifying signature");
    let pk = create_obj_from_Uint8Array!(public_key, PUBLIC_KEY_LENGTH, PublicKey, -1, -2);
    let sig = create_obj_from_Uint8Array!(signature, SIG_LENGTH, Signature, -3, -4);

    let msg = message.to_vec();
    let res = pk.verify(&msg, &sig);
    if res.is_ok() {
        log("verifying passed");
        0
    } else {
        log("verifying failed");
        -5
    }
}

/// An Ed25519ph [`Signature`] on the `prehashed_message`. [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
/// `prehashed_message` is expected to be a 64 byte hash
/// Does not accept context for now. context will be chosen as an empty string. See comment inside function for details
#[wasm_bindgen]
//pub fn sign_prehashed_with_secret_key(secret_key: Uint8Array, public_key: Uint8Array, prehashed_message: Uint8Array, context: Uint8Array, signature: &mut [u8]) -> i8 {
pub fn sign_prehashed_with_secret_key(
    secret_key: Uint8Array,
    public_key: Uint8Array,
    prehashed_message: Uint8Array,
    signature: &mut [u8],
) -> i8 {
    log("Got new request for signing prehashed message ");
    log(&format!("sk len is {}", secret_key.length()));
    log(&format!("pk len is {}", public_key.length()));
    let sk = create_obj_from_Uint8Array!(secret_key, SECRET_KEY_LENGTH, SecretKey, -1, -2);

    let pk = create_obj_from_Uint8Array!(public_key, PUBLIC_KEY_LENGTH, PublicKey, -3, -4);

    /*if context.length() != CTX_LENGTH as u32 {
        return -5
    }*/
    if prehashed_message.length() != PH_MSG_LENGTH as u32 {
        return -6;
    }

    if signature.len() != SIG_LENGTH {
        return -7;
    }

    let mut msg_bytes: GenericArray<u8, U64> = GenericArray::default();
    prehashed_message.copy_to(&mut msg_bytes);

    let exp_sk = ExpandedSecretKey::from(&sk);

    // TODO: Fix me. Dalek's `sign_prehashed` requires ctx_bytes to be static but making a
    // mutable static will make me use an unsafe block
    /*let mut ctx_bytes: [u8; CTX_LENGTH] = [0; CTX_LENGTH];
    context.copy_to(&mut ctx_bytes);*/

    let sig = exp_sk.sign_prehashed(Sha512Output { h: msg_bytes }, &pk, None);
    // TODO: Fix me.
    // let sig = exp_sk.sign_prehashed(d, &pk.unwrap(), Some(&'static ctx));
    signature.clone_from_slice(&sig.to_bytes());
    0
}

/// Verify signature on a pre-hashed message. [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
/// `prehashed_message` is expected to be a 64 byte hash. Returns 0 on successful verification
/// Does not accept context for now.
#[wasm_bindgen]
pub fn verify_prehashed(
    public_key: Uint8Array,
    prehashed_message: Uint8Array,
    signature: Uint8Array,
) -> i8 {
    log("Got new request for verifying signature over prehased message ");
    let pk = create_obj_from_Uint8Array!(public_key, PUBLIC_KEY_LENGTH, PublicKey, -1, -2);
    let sig = create_obj_from_Uint8Array!(signature, SIG_LENGTH, Signature, -3, -4);

    let mut msg_bytes: GenericArray<u8, U64> = GenericArray::default();
    prehashed_message.copy_to(&mut msg_bytes);

    let res = pk.verify_prehashed(Sha512Output { h: msg_bytes }, None, &sig);
    if res.is_ok() {
        log("verifying passed");
        0
    } else {
        log("verifying failed");
        -5
    }
}

#[wasm_bindgen]
pub fn verify_batch(public_keys: JsValue, messages: JsValue, signatures: JsValue) -> i8 {
    log("Got new request for verifying batch of signatures");
    let public_keys: Result<Vec<Vec<u8>>, Error> = public_keys.into_serde();
    let public_keys = {
        if public_keys.is_ok() {
            public_keys.unwrap()
        } else {
            return -1
        }
    };
    let messages: Result<Vec<Vec<u8>>, Error> = messages.into_serde();
    let messages = {
        if messages.is_ok() {
            messages.unwrap()
        } else {
            return -2
        }
    };
    let signatures: Result<Vec<Vec<u8>>, Error> = signatures.into_serde();
    let signatures = {
        if signatures.is_ok() {
            signatures.unwrap()
        } else {
            return -3
        }
    };
    if public_keys.len() == messages.len() && public_keys.len() == signatures.len() {
        let pks: Result<Vec<PublicKey>, _> = public_keys.into_iter().map(|pk| PublicKey::from_bytes(&pk)).collect();
        if pks.is_err() {
            return -5;
        }
        let pks = pks.unwrap();
        let sigs: Result<Vec<Signature>, _> = signatures.into_iter().map(|sig| Signature::from_bytes(&sig)).collect();
        if sigs.is_err() {
            return -6;
        }
        let sigs = sigs.unwrap();
        let msgs: Vec<&[u8]> = messages.iter().map(|m|m.as_slice()).collect();

        let res = dalek_verify_batch(&msgs, &sigs, &pks);
        if res.is_err() {
            return -7;
        }
        0
    } else {
        return -4
    }
}

// XXX: Consider having signing functions that accept expanded secret key
