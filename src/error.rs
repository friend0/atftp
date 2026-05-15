use std::io;

use thiserror::Error;

use crate::proto::ErrorCode;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("malformed packet: {0}")]
    Malformed(&'static str),

    #[error("unknown opcode: {0}")]
    UnknownOpcode(u16),

    #[error("invalid utf-8 in string field")]
    InvalidUtf8,

    #[error("string field missing NUL terminator")]
    MissingNul,

    #[error("invalid mode: {0:?}")]
    InvalidMode(String),

    #[error("invalid option value for {name}: {value}")]
    InvalidOption { name: String, value: String },

    #[error("peer reported error {code:?}: {msg}")]
    Peer { code: ErrorCode, msg: String },

    #[error("transfer timed out after {0} retries")]
    Timeout(u32),

    #[error("unexpected packet from peer")]
    UnexpectedPacket,

    #[error("path traversal or invalid filename: {0:?}")]
    InvalidPath(String),

    #[error("file too large for TFTP transfer")]
    FileTooLarge,

    #[error("transfer cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, Error>;
