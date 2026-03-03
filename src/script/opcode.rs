use primitive_types::U256;

use crate::{
    ecc::ecdsa::{PublicKey, Signature},
    script::{decode_num, encode_num},
    utils::hash160::{self, hash160},
};

fn op_0(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(0));
    return true;
}

fn op_1(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(1));
    return true;
}
fn op_2(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(2));
    return true;
}
pub fn op_3(stack: &mut Vec<Vec<u8>>) -> bool {
    stack.push(encode_num(3));
    return true;
}

pub fn op_dup(stack: &mut Vec<Vec<u8>>) -> bool {
    let Some(last_elem) = stack.last() else {
        return false;
    };

    stack.push(last_elem.clone());

    true
}
pub fn op_hash160_op(stack: &mut Vec<Vec<u8>>) -> bool {
    let Some(last_elem) = stack.pop() else {
        return false;
    };

    let hashed_elem = hash160(&last_elem).to_vec();
    stack.push(hashed_elem);
    true
}

pub fn op_equal(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let a = stack.pop().expect("length checked");
    let b = stack.pop().expect("length checked");

    let eq_result = if a == b { encode_num(1) } else { encode_num(0) };
    stack.push(eq_result);
    true
}

// --- OP_VERIFY: pop top, fail if zero ---
pub fn op_verify(stack: &mut Vec<Vec<u8>>) -> bool {
    let Some(last_elem) = stack.pop() else {
        return false;
    };

    let decoded_value = decode_num(&last_elem);

    decoded_value != 0
}

pub fn op_equalverify(stack: &mut Vec<Vec<u8>>) -> bool {
    op_equal(stack) && op_verify(stack)
}

pub fn op_add(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let a = stack.pop().expect("length checked");
    let b = stack.pop().expect("length checked");

    let (a, b) = (decode_num(&a), decode_num(&b));
    stack.push(encode_num(a + b));

    true
}

// check that there are at least 2 elements on the stack
// the top element of the stack is the SEC pubkey
// the next element of the stack is the DER signature
// take off the last byte of the signature as that's the hash_type
// parse the serialized pubkey and signature into objects
// verify the signature using S256Point.verify()
// push an encoded 1 or 0 depending on whether the signature verified
pub fn op_checksig(stack: &mut Vec<Vec<u8>>, z: U256) -> bool {
    if stack.len() < 2 {
        return false;
    }
    let sec_pubkey = stack.pop().expect("length checked");
    // take off the last byte of the signature as that's the hash_type
    let der_signature_raw = stack.pop().expect("length checked");
    let sig_bytes = &der_signature_raw[..der_signature_raw.len() - 1];

    // parse the serialized signature into object
    let Ok(signature) = Signature::parse(sig_bytes) else {
        return false;
    };

    // parse the serialized pubkey into object
    let pubkey: Option<PublicKey> = match sec_pubkey.first() {
        Some(0x04) => <&[u8; 65]>::try_from(sec_pubkey.as_slice())
            .ok()
            .and_then(|b| PublicKey::parse(b).ok()),
        Some(0x02) | Some(0x03) => <&[u8; 33]>::try_from(sec_pubkey.as_slice())
            .ok()
            .and_then(|b| PublicKey::parse_compressed(b).ok()),
        _ => None,
    };

    let Some(pubkey) = pubkey else {
        return false;
    };

    if pubkey.verify_signature(z, &signature) {
        stack.push(encode_num(1));
    } else {
        stack.push(encode_num(0));
    }
    true
}
