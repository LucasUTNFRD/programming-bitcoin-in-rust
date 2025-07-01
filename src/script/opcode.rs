use primitive_types::{H160, U256};

use crate::{
    ecc::ecdsa::{PublicKey, Signature},
    error::Error,
    script::StackItem,
    transactions::tx::ParseError,
    utils::{
        hash160::hash160,
        hash256::{self, hash256},
    },
};

use super::{ExecutionCtx, Script, ScriptCmd};

#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum OpCode {
    OP_0,
    OP_1,
    OP_16,
    OP_DUP,
    OP_ADD,
    OP_HASH160,
    OP_HASH256,
    OP_CHECKSIG,
    OP_EQUALVERIFY,
}

/// Takes a 20 byte hash to a ScriptPubKey
fn p2pkh_script(h160: H160) -> Script {
    Script::new(Some(
        [
            ScriptCmd::OpCode(OpCode::OP_DUP),
            ScriptCmd::OpCode(OpCode::OP_HASH160),
            ScriptCmd::Push(h160.as_bytes().to_vec()),
            ScriptCmd::OpCode(OpCode::OP_EQUALVERIFY),
            ScriptCmd::OpCode(OpCode::OP_CHECKSIG),
        ]
        .to_vec(),
    ))
}

impl OpCode {
    pub fn as_byte(&self) -> u8 {
        use OpCode::*;
        match self {
            OP_0 => 0x00,
            OP_1 => 0x51,
            OP_16 => 0x60,
            OP_DUP => 0x76,
            OP_ADD => 0x93,
            OP_HASH160 => 0xa9,
            OP_CHECKSIG => 0xac,
            OP_HASH256 => 0xAA,
            OP_EQUALVERIFY => 0x88,
        }
    }

    pub fn execute(&self, ctx: &mut ExecutionCtx, z: Option<U256>) -> Result<(), Error> {
        use OpCode::*;
        match self {
            OP_0 => ctx.stack.push(StackItem::Num(0)),
            OP_1 => ctx.stack.push(StackItem::Num(1)),
            OP_16 => ctx.stack.push(StackItem::Num(16)),
            OP_DUP => {
                if ctx.stack.is_empty() {
                    return Err(Error::EmptyStack);
                }
                let top = ctx.stack.last().ok_or(Error::EmptyStack)?.clone();
                ctx.stack.push(top);
            }
            OP_ADD => {
                if ctx.stack.len() < 2 {
                    return Err(Error::InvalidStackSize);
                }
                let b = ctx.stack.pop().ok_or(Error::EmptyStack)?;
                let a = ctx.stack.pop().ok_or(Error::EmptyStack)?;
                match (a, b) {
                    (StackItem::Num(a_val), StackItem::Num(b_val)) => {
                        ctx.stack.push(StackItem::Num(a_val.wrapping_add(b_val)));
                    }
                    _ => return Err(Error::InvalidStackOperation),
                }
            }
            OP_HASH160 => {
                if ctx.stack.is_empty() {
                    return Err(Error::EmptyStack);
                }
                let elem = ctx.stack.pop().ok_or(Error::EmptyStack)?;
                let hashed_value = match elem {
                    StackItem::Num(x) => hash160(&x.to_le_bytes()),
                    StackItem::RawData(data) => hash160(&data),
                };
                ctx.stack.push(StackItem::RawData(hashed_value.into()));
            }
            OP_CHECKSIG => {
                if ctx.stack.len() < 2 {
                    return Err(Error::InvalidStackSize);
                }

                let pub_key = if let Some(StackItem::RawData(pub_key_bytes)) = ctx.stack.pop() {
                    if pub_key_bytes.len() == 33 {
                        let mut key_array = [0u8; 33];
                        key_array.copy_from_slice(&pub_key_bytes);
                        PublicKey::parse_compressed(&key_array)?
                    } else if pub_key_bytes.len() == 65 {
                        let mut key_array = [0u8; 65];
                        key_array.copy_from_slice(&pub_key_bytes);
                        PublicKey::parse(&key_array)?
                    } else {
                        return Err(Error::InvalidPublicKey);
                    }
                } else {
                    // invalid stack item
                    return Err(Error::InvalidStackSize);
                };
                let signature = if let Some(StackItem::RawData(signature_bytes)) = ctx.stack.pop() {
                    Signature::parse(&signature_bytes)?
                } else {
                    return Err(Error::InvalidStackSize);
                };

                let z = z.ok_or(Error::MissingZ)?;
                pub_key.verify_signature(z, &signature);
                let is_valid = pub_key.verify_signature(z, &signature);

                ctx.stack.push(StackItem::Num(if is_valid { 1 } else { 0 }));
            }
            OP_HASH256 => {
                if ctx.stack.is_empty() {
                    return Err(Error::EmptyStack);
                }
                let elem = ctx.stack.pop().ok_or(Error::EmptyStack)?;
                let hashed_value = match elem {
                    StackItem::Num(x) => hash256(&x.to_le_bytes()),
                    StackItem::RawData(data) => hash256(&data),
                };
                ctx.stack.push(StackItem::RawData(hashed_value.into()));
            }
            OP_EQUALVERIFY => {
                todo!()
            }
        }

        Ok(())
    }
}

impl TryFrom<u8> for OpCode {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use OpCode::*;
        match value {
            0x00 => Ok(OP_0),
            0x51 => Ok(OP_1),
            0x60 => Ok(OP_16),
            0x76 => Ok(OP_DUP),
            0x93 => Ok(OP_ADD),
            0xa9 => Ok(OP_HASH160),
            0xac => Ok(OP_CHECKSIG),
            _ => Err(ParseError::InvalidOpCode),
        }
    }
}

pub(crate) const OP_PUSHDATA1: u8 = 76u8;
pub(crate) const OP_PUSHDATA2: u8 = 77u8;
pub(crate) const OP_PUSHDATA4: u8 = 78u8;
pub(crate) const OP_PUSHBYTES_1_START: u8 = 0x01;
pub(crate) const OP_PUSHBYTES_75_END: u8 = 0x4b;
