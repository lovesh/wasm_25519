extern crate ed25519_dalek;
extern crate x25519_dalek;

// Rand crate's version 0.7, used by x25519 crate
extern crate rand_07;

// Rand crate's version 0.6, used by ed25519 crate
extern crate rand_06;

extern crate generic_array;
extern crate js_sys;
extern crate sha2;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

pub mod dhe_25519;
pub mod sig_ed25519;
mod util;
