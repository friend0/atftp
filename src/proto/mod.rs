//! TFTP wire protocol — RFC 1350 plus the option-extension family
//! (RFC 2347, 2348, 2349, 7440).

mod opcode;
mod options;
mod packet;

pub use opcode::{ErrorCode, Opcode};
pub use options::{Mode, OptionSet, OptionValue};
pub use packet::{Packet, decode, encode_into};

/// Default block size before any blksize negotiation.
pub const DEFAULT_BLOCK_SIZE: u16 = 512;

/// Minimum block size that may be negotiated (RFC 2348).
pub const MIN_BLOCK_SIZE: u16 = 8;

/// Maximum block size that may be negotiated (RFC 2348). Larger values
/// risk IP fragmentation but are widely accepted; we cap at the IPv4
/// theoretical maximum payload to be safe.
pub const MAX_BLOCK_SIZE: u16 = 65464;

/// Default per-packet retransmit timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u8 = 5;

/// Default windowsize before any windowsize negotiation (RFC 7440).
pub const DEFAULT_WINDOW_SIZE: u16 = 1;

/// Maximum data payload an OACK / ERROR packet is allowed to consume.
/// Used as a sanity bound when parsing.
pub const MAX_PACKET_SIZE: usize = MAX_BLOCK_SIZE as usize + 4;
