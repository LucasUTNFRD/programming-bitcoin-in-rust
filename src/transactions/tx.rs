use std::{
    collections::HashMap,
    io::{Read, Write},
    path::Display,
};

use primitive_types::H256;
use thiserror::Error;

use crate::{script::Script, utils::hash256::hash256};

#[derive(Debug)]
pub struct Transaction {
    pub version: i32,
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
    pub network: BlockChain,
    pub locktime: u32,
}

impl std::fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Transaction {{ version: {}, inputs: {}, outputs: {}, locktime: {} }}",
            self.version,
            self.input.len(),
            self.output.len(),
            self.locktime
        )
    }
}

#[derive(Debug, Clone, Copy)]
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
    pub fn new(
        version: i32,
        input: Vec<TxIn>,
        output: Vec<TxOut>,
        network: BlockChain,
        locktime: u32,
    ) -> Self {
        Self {
            version,
            input,
            output,
            network,
            locktime,
        }
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
        // Parse output count (varint)
        let output_count = VarInt::read_varint(stream)?.value();
        let mut outputs = Vec::with_capacity(output_count as usize);

        // Parse each output
        for _ in 0..output_count {
            outputs.push(TxOut::parse(stream)?);
        }

        // Parse locktime (4 bytes, little-endian)
        let mut locktime_bytes = [0u8; 4];
        stream.read_exact(&mut locktime_bytes)?;
        let locktime = u32::from_le_bytes(locktime_bytes);

        Ok(Self::new(
            version,
            inputs,
            outputs,
            BlockChain::MainNet,
            locktime,
        ))
    }

    pub fn verify(&self) -> bool {
        for input in self.input.iter() {
            if !self.verify_input(input) {
                return false;
            }
        }

        true
    }

    fn verify_input(&self, input: &TxIn) -> bool {
        todo!()
    }

    ///It’s the hash256 of the transaction in hexadecimal format.
    pub fn id(&self) -> String {
        hex::encode(self.hash())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Version (4 bytes, little-endian)
        result.extend_from_slice(&self.version.to_le_bytes());

        // Input count (varint)
        result.extend_from_slice(&VarInt::encode_varint(self.input.len() as u64));

        // Inputs
        for input in &self.input {
            result.extend_from_slice(&input.serialize());
        }

        // Output count (varint)
        result.extend_from_slice(&VarInt::encode_varint(self.output.len() as u64));

        // Outputs
        for output in &self.output {
            result.extend_from_slice(&output.serialize());
        }

        // Locktime (4 bytes, little-endian)
        result.extend_from_slice(&self.locktime.to_le_bytes());

        result
    }

    ///The hash is the hash256 of the serialization in little-endian
    pub fn hash(&self) -> [u8; 32] {
        let mut h = hash256(&self.serialize());
        h.reverse();
        h
    }

    pub fn fee(&self) -> Amount {
        let input_sum: u64 = self
            .input
            .iter()
            .map(|tx_in| tx_in.value(self.network))
            .sum();
        let ouput_sum: u64 = self.output.iter().map(|tx_out| tx_out.amount).sum();
        input_sum - ouput_sum
    }
}

pub type Sequence = u32;
pub type TxID = [u8; 32];

#[derive(Debug)]
pub struct TxIn {
    prev_tx_id: TxID,
    prev_tx_idx: u32,
    pub sequence: Sequence,
    pub script_sig: Option<Script>,
}

impl TxIn {
    pub fn new(
        prev_tx_id: TxID,
        sequence: Sequence,
        script_sig: Option<Script>,
        prev_tx_idx: u32,
    ) -> Self {
        Self {
            prev_tx_id,
            sequence,
            script_sig,
            prev_tx_idx,
        }
    }

    /// Parse the following fields from stream
    ///     - previous transaction ID
    ///     - previous index
    ///     - ScriptSig
    ///     - Sequence
    pub fn parse(stream: &mut impl Read) -> Result<Self, ParseError> {
        let mut prev_tx_id = [0u8; 32];
        stream.read_exact(&mut prev_tx_id)?;

        let mut prev_idx_bytes = [0u8; 4];
        stream.read_exact(&mut prev_idx_bytes)?;
        let prev_tx_idx = u32::from_le_bytes(prev_idx_bytes);

        // TODO: use a dedicated function for ScriptSig parsing
        let script_sig = Script::decode(stream)?;

        let mut sequence_bytes = [0u8; 4];
        stream.read_exact(&mut sequence_bytes)?;
        let sequence = u32::from_le_bytes(sequence_bytes);

        Ok(Self::new(
            prev_tx_id,
            sequence,
            Some(script_sig),
            prev_tx_idx,
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        // Previous transaction ID (32 bytes)
        result.extend_from_slice(&self.prev_tx_id);

        // Previous transaction output index (4 bytes, little-endian)
        result.extend_from_slice(&self.prev_tx_idx.to_le_bytes());

        // TODO:
        // ScriptSig (variable length with varint prefix)
        // result.extend_from_slice(&self.script_sig.encode());

        // Sequence (4 bytes, little-endian)
        result.extend_from_slice(&self.sequence.to_le_bytes());
        result
    }

    pub fn fetch_tx(&self, testnet: bool) -> Transaction {
        todo!()
    }

    pub fn value(&self, testnet: BlockChain) -> Amount {
        todo!()
    }

    pub fn script_pubkey(&self, testnet: bool) -> Script {
        todo!()
    }
}

impl std::fmt::Display for TxOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TxOut {{ amount: {}, script_pubkey: {:?} }}",
            self.amount, self.script_pubkey
        )
    }
}

pub type Amount = u64;

#[derive(Debug)]
pub struct TxOut {
    amount: Amount,
    script_pubkey: Script,
}

impl TxOut {
    pub fn new(amount: Amount, script_pubkey: Script) -> Self {
        Self {
            amount,
            script_pubkey,
        }
    }

    /// Parse TxOut from stream:
    /// - amount (8 bytes, little-endian)
    /// - script_pubkey (variable length, prefixed with varint)
    pub fn parse(stream: &mut impl Read) -> Result<Self, ParseError> {
        let mut amount_bytes = [0u8; 8];
        stream.read_exact(&mut amount_bytes)?;
        let amount = u64::from_le_bytes(amount_bytes);

        // Script pubkey (variable length)
        let script_pubkey = Script::decode(stream)?;

        Ok(Self::new(amount, script_pubkey))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Amount (8 bytes, little-endian)
        result.extend_from_slice(&self.amount.to_le_bytes());

        // Script pubkey (variable length with varint prefix)
        result.extend_from_slice(&self.script_pubkey.encode());

        result
    }
}

pub struct TxFetcher {
    cache: HashMap<TxID, Transaction>,
}

impl TxFetcher {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
    pub fn get_url(&self, blockchain: BlockChain) -> &str {
        match blockchain {
            BlockChain::TestNet => "http://testnet.programmingbitcoin.com",
            BlockChain::MainNet => "http://mainnet.programmingbitcoin.com",
        }
    }

    pub fn fetch(
        &mut self,
        tx_id: TxID,
        blockchain: BlockChain,
        fresh: bool,
    ) -> Result<&Transaction, ParseError> {
        if !fresh && self.cache.contains_key(&tx_id) {
            return Ok(self.cache.get(&tx_id).unwrap());
        }

        // Implementation would involve HTTP request to fetch transaction
        todo!("Implement HTTP fetching of transaction data")
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_transaction_fee() {
        let raw_tx = hex::decode(
            "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600",
        ).unwrap();

        let mut stream = Cursor::new(raw_tx);

        let tx = Transaction::parse(&mut stream);
        assert!(tx.is_ok());
        let transaction = tx.unwrap();
        assert_eq!(transaction.version, 1);
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 2);
        assert_eq!(transaction.locktime, 410393);
    }
}
