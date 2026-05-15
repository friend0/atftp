use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::proto::{MAX_BLOCK_SIZE, MIN_BLOCK_SIZE};

/// Transfer mode field of RRQ/WRQ packets (RFC 1350 §2). The historic
/// `mail` mode is intentionally unsupported; it was deprecated in
/// RFC 1350 and never used in practice.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Mode {
    NetAscii,
    Octet,
}

impl Mode {
    pub fn as_wire(&self) -> &'static str {
        match self {
            Mode::NetAscii => "netascii",
            Mode::Octet => "octet",
        }
    }
}

impl FromStr for Mode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        // RFC 1350 §2: mode field is case-insensitive.
        if s.eq_ignore_ascii_case("netascii") {
            Ok(Mode::NetAscii)
        } else if s.eq_ignore_ascii_case("octet") || s.eq_ignore_ascii_case("binary") {
            Ok(Mode::Octet)
        } else {
            Err(Error::InvalidMode(s.to_owned()))
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// Parsed value for a known TFTP option. Unknown options are dropped
/// during parsing (RFC 2347: a server MUST silently ignore options it
/// does not understand and SHOULD NOT acknowledge them).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum OptionValue {
    /// blksize, RFC 2348.
    BlockSize(u16),
    /// timeout, RFC 2349 — per-packet retransmit timeout in seconds (1..=255).
    Timeout(u8),
    /// tsize, RFC 2349 — total transfer size in bytes. Sent as 0 by a
    /// client doing a read to ask the server how big the file is.
    TransferSize(u64),
    /// windowsize, RFC 7440.
    WindowSize(u16),
}

impl OptionValue {
    pub fn name(&self) -> &'static str {
        match self {
            OptionValue::BlockSize(_) => "blksize",
            OptionValue::Timeout(_) => "timeout",
            OptionValue::TransferSize(_) => "tsize",
            OptionValue::WindowSize(_) => "windowsize",
        }
    }

    pub fn value_string(&self) -> String {
        match self {
            OptionValue::BlockSize(v) => v.to_string(),
            OptionValue::Timeout(v) => v.to_string(),
            OptionValue::TransferSize(v) => v.to_string(),
            OptionValue::WindowSize(v) => v.to_string(),
        }
    }

    fn parse(name: &str, value: &str) -> Result<Self> {
        let invalid = || Error::InvalidOption {
            name: name.to_owned(),
            value: value.to_owned(),
        };
        if name.eq_ignore_ascii_case("blksize") {
            let n: u16 = value.parse().map_err(|_| invalid())?;
            if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&n) {
                return Err(invalid());
            }
            Ok(OptionValue::BlockSize(n))
        } else if name.eq_ignore_ascii_case("timeout") {
            let n: u8 = value.parse().map_err(|_| invalid())?;
            if n == 0 {
                return Err(invalid());
            }
            Ok(OptionValue::Timeout(n))
        } else if name.eq_ignore_ascii_case("tsize") {
            let n: u64 = value.parse().map_err(|_| invalid())?;
            Ok(OptionValue::TransferSize(n))
        } else if name.eq_ignore_ascii_case("windowsize") {
            let n: u16 = value.parse().map_err(|_| invalid())?;
            if n == 0 {
                return Err(invalid());
            }
            Ok(OptionValue::WindowSize(n))
        } else {
            // RFC 2347: caller is responsible for silently ignoring
            // unknown options. We surface this via a sentinel that the
            // packet decoder treats as "skip".
            Err(invalid())
        }
    }
}

/// An ordered set of options as they appeared on the wire. The order
/// matters because some peers care about it for OACK echoing; we keep
/// insertion order via `Vec` while still supporting de-duplication.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OptionSet {
    items: Vec<OptionValue>,
}

impl OptionSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &OptionValue> {
        self.items.iter()
    }

    /// Insert an option, replacing any prior value of the same kind.
    pub fn insert(&mut self, value: OptionValue) {
        if let Some(slot) = self
            .items
            .iter_mut()
            .find(|existing| existing.name() == value.name())
        {
            *slot = value;
        } else {
            self.items.push(value);
        }
    }

    pub fn block_size(&self) -> Option<u16> {
        self.items.iter().find_map(|o| match o {
            OptionValue::BlockSize(v) => Some(*v),
            _ => None,
        })
    }

    pub fn timeout(&self) -> Option<u8> {
        self.items.iter().find_map(|o| match o {
            OptionValue::Timeout(v) => Some(*v),
            _ => None,
        })
    }

    pub fn transfer_size(&self) -> Option<u64> {
        self.items.iter().find_map(|o| match o {
            OptionValue::TransferSize(v) => Some(*v),
            _ => None,
        })
    }

    pub fn window_size(&self) -> Option<u16> {
        self.items.iter().find_map(|o| match o {
            OptionValue::WindowSize(v) => Some(*v),
            _ => None,
        })
    }

    /// Parse from a sequence of (name, value) NUL-terminated string
    /// pairs. Unknown options are silently dropped per RFC 2347.
    pub(crate) fn from_pairs(pairs: &[(String, String)]) -> Self {
        // Dedup by name, last-write-wins, while preserving first-occurrence order.
        let mut order: Vec<String> = Vec::new();
        let mut latest: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in pairs {
            let lower = k.to_ascii_lowercase();
            if !order.iter().any(|n| n == &lower) {
                order.push(lower.clone());
            }
            latest.insert(lower, v.clone());
        }
        let mut set = OptionSet::new();
        for name in &order {
            if let Some(value) = latest.get(name) {
                if let Ok(opt) = OptionValue::parse(name, value) {
                    set.insert(opt);
                }
            }
        }
        set
    }
}
