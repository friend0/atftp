use crate::error::{Error, Result};

/// TFTP opcodes — first two bytes of every packet (RFC 1350 §5).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Opcode {
    Rrq = 1,
    Wrq = 2,
    Data = 3,
    Ack = 4,
    Error = 5,
    /// RFC 2347 Option Acknowledgement.
    Oack = 6,
}

impl Opcode {
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            1 => Ok(Opcode::Rrq),
            2 => Ok(Opcode::Wrq),
            3 => Ok(Opcode::Data),
            4 => Ok(Opcode::Ack),
            5 => Ok(Opcode::Error),
            6 => Ok(Opcode::Oack),
            other => Err(Error::UnknownOpcode(other)),
        }
    }
}

/// TFTP error codes (RFC 1350 §5 + RFC 2347 §6 for code 8).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    NotDefined = 0,
    FileNotFound = 1,
    AccessViolation = 2,
    DiskFull = 3,
    IllegalOperation = 4,
    UnknownTid = 5,
    FileExists = 6,
    NoSuchUser = 7,
    /// RFC 2347 — option negotiation refused.
    OptionNegotiation = 8,
}

impl ErrorCode {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => ErrorCode::FileNotFound,
            2 => ErrorCode::AccessViolation,
            3 => ErrorCode::DiskFull,
            4 => ErrorCode::IllegalOperation,
            5 => ErrorCode::UnknownTid,
            6 => ErrorCode::FileExists,
            7 => ErrorCode::NoSuchUser,
            8 => ErrorCode::OptionNegotiation,
            _ => ErrorCode::NotDefined,
        }
    }
}
