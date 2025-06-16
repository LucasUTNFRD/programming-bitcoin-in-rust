use std::io::Read;

use thiserror::Error;

#[derive(Debug)]
pub struct Transaction {
    pub version: i32,
    pub input: TxIn,
    pub output: TxOut,
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
}

pub struct VarInt(pub u64);

impl VarInt {
    pub const fn size(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
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

    // pub fn write_varint(&self) -> Vec<u8> {}
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

        let input_count = VarInt::read_varint(stream)?;

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

#[derive(Debug)]
pub struct TxIn {
    // prev_tx: Tx,
}

impl TxIn {
    pub fn new() -> Self {
        todo!()
    }

    pub fn serialize() {
        todo!()
    }
}

#[derive(Debug)]
pub struct TxOut {}

impl TxOut {
    pub fn new() -> Self {
        todo!()
    }

    pub fn serialize() {
        todo!()
    }
}
