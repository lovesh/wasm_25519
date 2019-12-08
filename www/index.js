import * as wasm from "wasm_25519";

function Utf8MsgToBytes(msg) {
    return new TextEncoder("utf-8").encode(msg);
}

function byteToHexString(uint8arr) {
  if (!uint8arr) {
    return '';
  }

  var hexStr = '';
  for (var i = 0; i < uint8arr.length; i++) {
    var hex = (uint8arr[i] & 0xff).toString(16);
    hex = (hex.length === 1) ? '0' + hex : hex;
    hexStr += hex;
  }

  return hexStr.toUpperCase();
}

function hexStringToByte(str) {
  if (!str) {
    return new Uint8Array();
  }

  var a = [];
  for (var i = 0, len = str.length; i < len; i+=2) {
    a.push(parseInt(str.substr(i,2),16));
  }

  return new Uint8Array(a);
}

export function genKeypair() {
    const secret_key = new Uint8Array(32);
    const public_key = new Uint8Array(32);
    var r = wasm.new_dh_keypair(secret_key, public_key);
    if (r != 0) {
        alert("Error while generating keys. Error code is " + r)
        return r;
    }
    return [secret_key, public_key];
};

export function genSharedSecret(my_secret_key, their_public_key) {
    const shared_secret = new Uint8Array(32);
    var r = wasm.dh_key_exchange(my_secret_key, their_public_key, shared_secret);
    if (r != 0) {
        alert("Error while generating shared secret. Error code is " + r)
        return r;
    }
    return shared_secret;
};

export function x25519(my_secret_key, their_public_key) {
    const shared_secret = new Uint8Array(32);
    var r = wasm.x25519_key_exchange(my_secret_key, their_public_key, shared_secret);
    if (r != 0) {
            alert("Error during x25591. Error code is " + r)
            return r;
        }
    return shared_secret;
};

export function genSigKeypair() {
    const secret_key = new Uint8Array(32);
    const public_key = new Uint8Array(32);
    var r = wasm.new_sig_keypair(secret_key, public_key);
    if (r != 0) {
        alert("Error during generating signing keypair. Error code is " + r)
        return r;
    }
    return [secret_key, public_key];
};

export function genSig(secret_key, public_key, message) {
    const sig = new Uint8Array(64);
    var r = wasm.sign_with_secret_key(secret_key, public_key, message, sig);
    if (r != 0) {
        alert("Error during generating signature. Error code is " + r)
        return r;
    }
    return sig;
};

export function verifySig(public_key, message, signature) {
    var r = wasm.verify(public_key, message, signature);
    return r;
};

export function genSigPreHashedMsg(secret_key, public_key, message) {
    const sig = new Uint8Array(64);
    var r = wasm.sign_prehashed_with_secret_key(secret_key, public_key, message, sig);
    if (r != 0) {
        alert("Error during generating signature. Error code is " + r)
        return r;
    }
    return sig;
};

export function verifySigPreHashedMsg(public_key, message, signature) {
    var r = wasm.verify_prehashed(public_key, message, signature);
    return r;
};

function newKeypair() {
   // Not doing any error handling
   var k = genKeypair();
   var sk = k[0];
   var pk = k[1];
   document.getElementById("keys").style.display = "block";
   document.getElementById("sk").innerText = "0x" + byteToHexString(sk);
   document.getElementById("pk").innerText = "0x" + byteToHexString(pk);
}

function newSharedSecret() {
   // Not doing any input validation
   var sk = document.getElementById("your_sk").value.slice(2);
   var pk = document.getElementById("their_pk").value.slice(2);
   // Not doing any error handling
   let shared_secret = genSharedSecret(hexStringToByte(sk), hexStringToByte(pk))
   document.getElementById("dhe_shared_secret").style.display = "block";
   document.getElementById("dhe_ss").innerText = "0x" + byteToHexString(shared_secret);

}

function newx25519Secret() {
   // Not doing any input validation
   var sk = document.getElementById("x25519_your_sk").value.slice(2);
   var pk = document.getElementById("x25519_their_pk").value.slice(2);
   // Not doing any error handling
   let shared_secret = genSharedSecret(hexStringToByte(sk), hexStringToByte(pk))
   document.getElementById("x25519_shared_secret").style.display = "block";
   document.getElementById("x25519_ss").innerText = "0x" + byteToHexString(shared_secret);

}

function newSigKeypair() {
   // Not doing any error handling
   var k = genSigKeypair();
   var sk = k[0];
   var pk = k[1];
   document.getElementById("sig_keys").style.display = "block";
   document.getElementById("sig_sk").innerText = "0x" + byteToHexString(sk);
   document.getElementById("sig_pk").innerText = "0x" + byteToHexString(pk);
}

function newSignature() {
   // Not doing any input validation
   var sk = document.getElementById("sig_sk_val").value.slice(2);
   var pk = document.getElementById("sig_pk_val").value.slice(2);
   var msg = Utf8MsgToBytes(document.getElementById("sig_msg").value);
   // Not doing any error handling
   let sig = genSig(hexStringToByte(sk), hexStringToByte(pk), msg)
   document.getElementById("sig").style.display = "block";
   document.getElementById("sig_val").innerText = "0x" + byteToHexString(sig);

}

function verifySignature() {
   // Not doing any input validation
   var sig = document.getElementById("ver_sig").value.slice(2);
   var pk = document.getElementById("ver_sig_pk_val").value.slice(2);
   var msg = Utf8MsgToBytes(document.getElementById("ver_sig_msg").value);
   // Not doing any error handling
   let res = verifySig(hexStringToByte(pk), msg, hexStringToByte(sig));
   if (res == 0) {
    document.getElementById("ver_result").innerText = "Signature verified successfully";
   } else {
    document.getElementById("ver_result").innerText = "Signature verification failed";
   }
}

function newSignaturePreHashedMsg() {
   // Not doing any input validation
   var sk = document.getElementById("sig_ph_sk_val").value.slice(2);
   var pk = document.getElementById("sig_ph_pk_val").value.slice(2);
   // Message is already hashed, so expecting hex
   var msg = document.getElementById("sig_ph_msg").value.slice(2);
   // Not doing any error handling
   let sig = genSigPreHashedMsg(hexStringToByte(sk), hexStringToByte(pk), hexStringToByte(msg))
   document.getElementById("sig_ph").style.display = "block";
   document.getElementById("sig_ph_val").innerText = "0x" + byteToHexString(sig);

}

function verifySignaturePreHashedMsg() {
   // Not doing any input validation
   var sig = document.getElementById("ver_sig_ph").value.slice(2);
   var pk = document.getElementById("ver_sig_ph_pk_val").value.slice(2);
   // Message is already hashed, so expecting hex
   var msg = document.getElementById("ver_sig_ph_msg").value.slice(2);
   // Not doing any error handling
   let res = verifySigPreHashedMsg(hexStringToByte(pk), hexStringToByte(msg), hexStringToByte(sig));
   if (res == 0) {
    document.getElementById("ver_ph_result").innerText = "Signature verified successfully";
   } else {
    document.getElementById("ver_ph_result").innerText = "Signature verification failed";
   }
}

document.getElementById("new_kp_button").addEventListener("click", newKeypair);
document.getElementById("dhe_ss_button").addEventListener("click", newSharedSecret);
document.getElementById("x25519_ss_button").addEventListener("click", newx25519Secret);

document.getElementById("new_sig_kp_button").addEventListener("click", newSigKeypair);
document.getElementById("sig_button").addEventListener("click", newSignature);
document.getElementById("ver_sig_button").addEventListener("click", verifySignature);
document.getElementById("sig_ph_button").addEventListener("click", newSignaturePreHashedMsg);
document.getElementById("ver_sig_ph_button").addEventListener("click", verifySignaturePreHashedMsg);