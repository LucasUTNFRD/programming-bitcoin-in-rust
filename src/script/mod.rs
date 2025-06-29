use std::io::Write;

use opcode::*;
use primitive_types::U256;
mod opcode;

use crate::{
    // error::Error,
    error::Error,
    transactions::tx::{ParseError, VarInt},
};

#[derive(Debug, Clone)]
pub struct Script {
    cmds: Vec<ScriptCmd>,
}

#[derive(Debug, Clone)]
pub enum ScriptCmd {
    OpCode(OpCode),
    Push(Vec<u8>),
}

impl ScriptCmd {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            ScriptCmd::OpCode(opcode) => {
                vec![opcode.as_byte()]
            }
            ScriptCmd::Push(data) => {
                let data_len = data.len();
                let size = match data_len {
                    0..=75 => 1 + data_len,
                    76..=255 => 2 + data_len,
                    256..=520 => 3 + data_len,
                    _ => {
                        panic!("to long an cmd")
                    }
                };
                let mut buf = Vec::with_capacity(size);
                buf.write_all(&[data_len as u8]).unwrap();
                buf.write_all(data).unwrap();
                buf
            }
        }
    }
}

impl Script {
    pub fn new(cmds: Option<Vec<ScriptCmd>>) -> Self {
        Script {
            cmds: cmds.unwrap_or_default(),
        }
    }

    pub fn concat(self, other: Script) -> Self {
        let mut commands = self.cmds;
        commands.extend(other.cmds);
        Self { cmds: commands }
    }

    pub fn decode(stream: &mut impl std::io::Read) -> Result<Self, ParseError> {
        let length = VarInt::read_varint(stream)?;
        let mut cmds = Vec::new();
        let mut count = 0u64;

        while count < length.value() {
            let mut current_bytes = [0u8; 1];
            stream.read_exact(&mut current_bytes)?;
            let current_byte = current_bytes[0];
            count += 1;

            match current_byte {
                OP_PUSHBYTES_1_START..=OP_PUSHBYTES_75_END => {
                    let n = current_byte as usize;
                    let mut data = vec![0u8; n];
                    stream.read_exact(&mut data)?;
                    count += n as u64;
                    cmds.push(ScriptCmd::Push(data));
                }
                OP_PUSHDATA1 => {
                    let mut len_buf = [0u8; 1];
                    stream.read_exact(&mut len_buf)?;
                    let data_length = len_buf[0] as usize;
                    let mut data = vec![0u8; data_length];
                    stream.read_exact(&mut data)?;
                    count += 1 + data_length as u64;
                    cmds.push(ScriptCmd::Push(data));
                }
                OP_PUSHDATA2 => {
                    let mut len_buf = [0u8; 2];
                    stream.read_exact(&mut len_buf)?;
                    let data_length = u16::from_le_bytes(len_buf) as usize;
                    let mut data = vec![0u8; data_length];
                    stream.read_exact(&mut data)?;
                    count += 2 + data_length as u64;
                    cmds.push(ScriptCmd::Push(data));
                }
                OP_PUSHDATA4 => {
                    let mut len_buf = [0u8; 4];
                    stream.read_exact(&mut len_buf)?;
                    let data_length = u32::from_le_bytes(len_buf) as usize;
                    let mut data = vec![0u8; data_length];
                    stream.read_exact(&mut data)?;
                    count += 4 + data_length as u64;
                    cmds.push(ScriptCmd::Push(data));
                }
                _ => {
                    // Regular opcode
                    let opcode = ScriptCmd::OpCode(OpCode::try_from(current_byte)?);
                    cmds.push(opcode);
                }
            }
        }

        if count != length.value() {
            // should panic here?
            return Err(ParseError::InvalidFormat);
        }

        Ok(Script { cmds })
    }

    fn raw_serialize(&self) -> Vec<u8> {
        self.cmds.iter().flat_map(|cmd| cmd.to_bytes()).collect()
    }

    // serialize creates the full byte representation of the script, prefixed with its VarInt length.
    pub fn encode(&self) -> Vec<u8> {
        let raw_script = self.raw_serialize();
        let mut result = VarInt::encode_varint(raw_script.len() as u64);
        result.extend_from_slice(&raw_script);
        result
    }

    /// given a combined command set
    pub fn execute(&self, z: Option<U256>) -> Result<bool, Error> {
        let mut ctx = ExecutionCtx::default();
        for cmd in self.cmds.iter() {
            match cmd {
                ScriptCmd::OpCode(op) => {
                    op.execute(&mut ctx, z)?;
                }
                ScriptCmd::Push(data) => {
                    ctx.stack.push(StackItem::RawData(data.clone()));
                }
            }
        }

        if ctx.stack.is_empty() {
            return Ok(false);
        }

        // The top value should be truthy (non-empty and non-zero)
        let top = ctx.stack.pop().unwrap();
        match top {
            StackItem::Num(n) => Ok(n != 0),
            StackItem::RawData(data) => Ok(!data.is_empty() && data != vec![0]),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExecutionCtx {
    stack: Vec<StackItem>,
    alt_stack: Vec<StackItem>,
}

#[derive(Debug, Clone)]
pub(crate) enum StackItem {
    Num(i32),
    RawData(Vec<u8>),
}

impl ExecutionCtx {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            alt_stack: Vec::new(),
        }
    }
}

impl Default for ExecutionCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic_script_evaluation() {
        let z = U256::from_str_radix(
            "0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
            16,
        )
        .unwrap();

        let sec = "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34";
        let sec_encode = hex::decode(sec).unwrap();
        let sig = "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        let sig_encode = hex::decode(sig).unwrap();

        let script_cmds = [
            ScriptCmd::Push(sec_encode),
            ScriptCmd::OpCode(OpCode::OP_CHECKSIG),
        ];
        let script_pubkey = Script::new(Some(script_cmds.to_vec()));
        let script_sig = Script::new(Some([ScriptCmd::Push(sig_encode)].to_vec()));
        let combined_script = script_sig.concat(script_pubkey);

        assert!(combined_script.execute(Some(z)).is_ok())
    }
}
