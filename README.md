# WASM for key exchange and signing using curve25519 and ed25519

- Uses [Dalek's x25519](https://github.com/dalek-cryptography/x25519-dalek) for Diffie-Hellman key exchange and x25519 which is another Diffie-Hellman key exchange but follows RFC7748.
- Uses [Dalek's ed25519](https://github.com/dalek-cryptography/ed25519-dalek) for signing over ed25519 curve.

 Demo UI for testing the generated wasm is present in `www` folder.  
1. Run `wasm-pack build` (in root) to generate wasm code.
2. Run `npm install` and `npm run start` from `www` to start a server and visit http://localhost:8080/ to use the Demo UI.

**Note: I created this to get started with WASM so quite likely there are better ways of doing things.**   