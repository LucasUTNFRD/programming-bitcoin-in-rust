use std::io::{Read, Write};

use thiserror::Error;

use crate::script::Script;

#[derive(Debug)]
pub struct Transaction {
    pub version: i32,
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
    pub network: BlockChain,
}

#[derive(Debug)]
pub enum BlockChain {
    TestNet,
    MainNet,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid transaction format")]
    InvalidFormat,
    #[error("Unexpected end of stream")]
    UnexpectedEof,
    #[error("Invalid varint encoding")]
    InvalidVarInt,
    #[error("Invalid OpCode")]
    InvalidOpCode,
}

pub struct VarInt(pub u64);

impl VarInt {
    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn read_varint(stream: &mut impl Read) -> Result<Self, ParseError> {
        let mut prefix = [0u8; 1];
        stream.read_exact(&mut prefix)?;

        let value = match prefix[0] {
            0..=0xFC => prefix[0] as u64,
            0xFD => {
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf)?;
                u16::from_le_bytes(buf) as u64
            }
            0xFE => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf)?;
                u32::from_le_bytes(buf) as u64
            }
            0xFF => {
                let mut buf = [0u8; 8];
                stream.read_exact(&mut buf)?;
                u64::from_le_bytes(buf)
            }
        };

        Ok(VarInt(value))
    }

    pub fn encode_varint(i: u64) -> Vec<u8> {
        match i {
            0..=0xfc => vec![i as u8],
            0xfd..=0xffff => {
                let mut result = Vec::with_capacity(1 + 2);
                result.push(0xfd);
                result.extend_from_slice(&(i as u16).to_le_bytes());
                result
            }
            0x10000..=0xffffffff => {
                let mut result = Vec::with_capacity(1 + 4);
                result.push(0xfe);
                result.extend_from_slice(&(i as u32).to_le_bytes());
                result
            }
            _ => {
                let mut result = Vec::with_capacity(1 + 8); // Allocate space for prefix + 8 bytes
                result.push(0xff); // Add the prefix byte
                result.extend_from_slice(&i.to_le_bytes());
                result
            }
        }
    }
}

impl Transaction {
    pub fn new() -> Self {
        todo!()
        // Self
    }

    pub fn parse(stream: &mut impl Read) -> Result<Self, ParseError> {
        let mut version_bytes = [0u8; 4];
        stream.read_exact(&mut version_bytes)?;
        let version = i32::from_le_bytes(version_bytes);

        let input_count = VarInt::read_varint(stream)?.value();
        let mut inputs = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            inputs.push(TxIn::parse(stream)?);
        }
        todo!()
    }

    ///It’s the hash256 of the transaction in hexadecimal format.
    pub fn id(&self) -> String {
        todo!()
    }

    ///The hash is the hash256 of the serialization in little-endian
    pub fn hash(&self) {
        todo!()
    }
}

pub type Sequence = u32;

#[derive(Debug)]
pub struct TxIn {
    prev_tx: TxOut,
    pub sequence: Sequence,
    pub script_sig: Option<Script>,
}

impl TxIn {
    pub fn new(prev_tx: TxOut) -> Self {
        todo!()
    }

    pub fn parse(stream: &mut impl Read) -> Result<Self, ParseError> {
        todo!()
    }

    pub fn serialize() {
        todo!()
    }

    pub fn fetch_tx(&self, testnet: bool) -> Transaction {
        todo!()
    }

    pub fn value(&self, testnet: bool) -> Amount {
        todo!()
    }

    pub fn script_subkey(&self, testnet: bool) -> Script {
        todo!()
    }

    pub fn fee() -> u64 {
        todo!()
    }
}

pub type Amount = u64;

#[derive(Debug)]
pub struct TxOut {
    amount: Amount,
    script_pubkey: Script,
}

impl TxOut {
    pub fn new() -> Self {
        todo!()
    }

    pub fn decode(stream: &mut impl Read) -> Result<Self, ParseError> {
        let mut version_bytes = [0u8; 4];
        stream.read_exact(&mut version_bytes)?;
        let version = i32::from_le_bytes(version_bytes);

        let input_count = VarInt::read_varint(stream)?;

        todo!()
    }

    pub fn encode(&self, writer: &mut impl Write) -> Vec<u8> {
        todo!()
    }
}
