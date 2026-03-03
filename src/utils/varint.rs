use std::io::Read;

use crate::transactions::tx::ParseError;

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
