use crate::util::log;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use x25519_dalek::{x25519, PublicKey, SharedSecret, StaticSecret};

// Should i make it u8 to save bytes? Don't know if the compiler can take care of that. Should check.
const PUBLIC_KEY_LENGTH: usize = 32;
const SECRET_KEY_LENGTH: usize = 32;
const SHARED_SECRET_LENGTH: usize = 32;

// Following functions don't return a Uint8Array but take a mutable reference to put the result in.
// This is done for the lack of ability to return Err to Wasm

/// Create a new keypair which will be used for Diffie-Hellman key exchange.
/// On success, returns 0
#[wasm_bindgen]
pub fn new_dh_keypair(secret_key: &mut [u8], public_key: &mut [u8]) -> i8 {
    log("Got new keygen request for key exchange");
    log(&format!("sk len is {}", secret_key.len()));
    log(&format!("pk len is {}", public_key.len()));
    if secret_key.len() != SECRET_KEY_LENGTH {
        return -1;
    }
    if public_key.len() != PUBLIC_KEY_LENGTH {
        return -2;
    }
    let mut rng = rand_07::thread_rng();
    let sk = StaticSecret::new(&mut rng);
    let pk = PublicKey::from(&sk);
    // sk and pk will be dropped when the function exits
    secret_key.clone_from_slice(&sk.to_bytes());
    public_key.clone_from_slice(pk.as_bytes());
    0
}

/// Do a Diffie-Hellman key exchange.
/// On success, returns 0
#[wasm_bindgen]
pub fn dh_key_exchange(
    my_secret_key: Uint8Array,
    their_public_key: Uint8Array,
    shared_secret: &mut [u8],
) -> i8 {
    log("Got DH key exchange request");
    log(&format!("sk len is {}", my_secret_key.length()));
    log(&format!("pk len is {}", their_public_key.length()));
    if my_secret_key.length() != SECRET_KEY_LENGTH as u32 {
        return -1;
    }
    if their_public_key.length() != PUBLIC_KEY_LENGTH as u32 {
        return -2;
    }
    if shared_secret.len() != (SHARED_SECRET_LENGTH as usize) {
        return -3;
    }

    let mut sk_bytes: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
    let mut pk_bytes: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
    my_secret_key.copy_to(&mut sk_bytes);
    their_public_key.copy_to(&mut pk_bytes);

    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(pk_bytes);
    // sk and pk will be dropped when the function exits
    let ss = sk.diffie_hellman(&pk);
    shared_secret.clone_from_slice(ss.as_bytes());
    0
}

/// Do a x2559 key exchange.
/// On success, returns 0
#[wasm_bindgen]
pub fn x25519_key_exchange(
    my_secret_key: Uint8Array,
    their_public_key: Uint8Array,
    shared_secret: &mut [u8],
) -> i8 {
    log("Got x25519 key exchange request");
    log(&format!("sk len is {}", my_secret_key.length()));
    log(&format!("pk len is {}", their_public_key.length()));
    if my_secret_key.length() != SECRET_KEY_LENGTH as u32 {
        return -1;
    }
    if their_public_key.length() != PUBLIC_KEY_LENGTH as u32 {
        return -2;
    }
    if shared_secret.len() != SHARED_SECRET_LENGTH {
        return -3;
    }

    let mut sk_bytes: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
    let mut pk_bytes: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
    my_secret_key.copy_to(&mut sk_bytes);
    their_public_key.copy_to(&mut pk_bytes);

    // sk and pk will be dropped when the function exits
    let ss = x25519(sk_bytes, pk_bytes);
    shared_secret.clone_from_slice(&ss);
    0
}
