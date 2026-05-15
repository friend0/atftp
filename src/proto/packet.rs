use bytes::{BufMut, BytesMut};

use crate::error::{Error, Result};
use crate::proto::opcode::{ErrorCode, Opcode};
use crate::proto::options::{Mode, OptionSet};

/// A decoded TFTP packet. Borrowed bytes (filename, error message,
/// data payload) are sliced from the source buffer where possible,
/// keeping the parser zero-copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet<'a> {
    Rrq {
        filename: String,
        mode: Mode,
        options: OptionSet,
    },
    Wrq {
        filename: String,
        mode: Mode,
        options: OptionSet,
    },
    Data {
        block: u16,
        data: &'a [u8],
    },
    Ack {
        block: u16,
    },
    Error {
        code: ErrorCode,
        msg: String,
    },
    Oack {
        options: OptionSet,
    },
}

/// Decode a single TFTP packet from the wire.
pub fn decode(buf: &[u8]) -> Result<Packet<'_>> {
    if buf.len() < 2 {
        return Err(Error::Malformed("packet shorter than opcode"));
    }
    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    let opcode = Opcode::from_u16(opcode)?;
    let body = &buf[2..];
    match opcode {
        Opcode::Rrq | Opcode::Wrq => decode_request(opcode, body),
        Opcode::Data => decode_data(body),
        Opcode::Ack => decode_ack(body),
        Opcode::Error => decode_error(body),
        Opcode::Oack => decode_oack(body),
    }
}

/// Encode a packet onto the end of `out`.
pub fn encode_into(packet: &Packet<'_>, out: &mut BytesMut) {
    match packet {
        Packet::Rrq {
            filename,
            mode,
            options,
        } => encode_request(Opcode::Rrq, filename, *mode, options, out),
        Packet::Wrq {
            filename,
            mode,
            options,
        } => encode_request(Opcode::Wrq, filename, *mode, options, out),
        Packet::Data { block, data } => {
            out.put_u16(Opcode::Data as u16);
            out.put_u16(*block);
            out.put_slice(data);
        }
        Packet::Ack { block } => {
            out.put_u16(Opcode::Ack as u16);
            out.put_u16(*block);
        }
        Packet::Error { code, msg } => {
            out.put_u16(Opcode::Error as u16);
            out.put_u16(*code as u16);
            out.put_slice(msg.as_bytes());
            out.put_u8(0);
        }
        Packet::Oack { options } => {
            out.put_u16(Opcode::Oack as u16);
            for opt in options.iter() {
                put_cstr(out, opt.name().as_bytes());
                put_cstr(out, opt.value_string().as_bytes());
            }
        }
    }
}

fn encode_request(
    opcode: Opcode,
    filename: &str,
    mode: Mode,
    options: &OptionSet,
    out: &mut BytesMut,
) {
    out.put_u16(opcode as u16);
    put_cstr(out, filename.as_bytes());
    put_cstr(out, mode.as_wire().as_bytes());
    for opt in options.iter() {
        put_cstr(out, opt.name().as_bytes());
        put_cstr(out, opt.value_string().as_bytes());
    }
}

fn put_cstr(out: &mut BytesMut, s: &[u8]) {
    out.put_slice(s);
    out.put_u8(0);
}

fn decode_request(opcode: Opcode, body: &[u8]) -> Result<Packet<'_>> {
    let mut cursor = body;
    let filename = take_cstr(&mut cursor)?;
    let mode_str = take_cstr(&mut cursor)?;
    let mode: Mode = mode_str.parse()?;
    let mut pairs = Vec::new();
    while !cursor.is_empty() {
        let name = take_cstr(&mut cursor)?;
        let value = take_cstr(&mut cursor)?;
        pairs.push((name, value));
    }
    let options = OptionSet::from_pairs(&pairs);
    match opcode {
        Opcode::Rrq => Ok(Packet::Rrq {
            filename,
            mode,
            options,
        }),
        Opcode::Wrq => Ok(Packet::Wrq {
            filename,
            mode,
            options,
        }),
        _ => unreachable!(),
    }
}

fn decode_data(body: &[u8]) -> Result<Packet<'_>> {
    if body.len() < 2 {
        return Err(Error::Malformed("DATA missing block number"));
    }
    let block = u16::from_be_bytes([body[0], body[1]]);
    Ok(Packet::Data {
        block,
        data: &body[2..],
    })
}

fn decode_ack(body: &[u8]) -> Result<Packet<'_>> {
    if body.len() < 2 {
        return Err(Error::Malformed("ACK missing block number"));
    }
    let block = u16::from_be_bytes([body[0], body[1]]);
    Ok(Packet::Ack { block })
}

fn decode_error(body: &[u8]) -> Result<Packet<'_>> {
    if body.len() < 3 {
        return Err(Error::Malformed("ERROR too short"));
    }
    let code = ErrorCode::from_u16(u16::from_be_bytes([body[0], body[1]]));
    let mut cursor = &body[2..];
    let msg = take_cstr(&mut cursor)?;
    Ok(Packet::Error { code, msg })
}

fn decode_oack(body: &[u8]) -> Result<Packet<'_>> {
    let mut cursor = body;
    let mut pairs = Vec::new();
    while !cursor.is_empty() {
        let name = take_cstr(&mut cursor)?;
        let value = take_cstr(&mut cursor)?;
        pairs.push((name, value));
    }
    let options = OptionSet::from_pairs(&pairs);
    Ok(Packet::Oack { options })
}

/// Consume a NUL-terminated ASCII string from `cursor`. Validates UTF-8
/// (RFC 1350 only requires netascii but every real-world implementation
/// uses ASCII filenames, and UTF-8 is a strict superset).
fn take_cstr(cursor: &mut &[u8]) -> Result<String> {
    let nul = cursor
        .iter()
        .position(|b| *b == 0)
        .ok_or(Error::MissingNul)?;
    let s = std::str::from_utf8(&cursor[..nul]).map_err(|_| Error::InvalidUtf8)?;
    let owned = s.to_owned();
    *cursor = &cursor[nul + 1..];
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::options::OptionValue;

    fn roundtrip(packet: Packet<'_>) {
        let mut buf = BytesMut::new();
        encode_into(&packet, &mut buf);
        let bytes = buf.freeze();
        let decoded = decode(&bytes).unwrap();
        // Compare via debug — owned vs borrowed slice parity is structural.
        assert_eq!(format!("{packet:?}"), format!("{decoded:?}"));
    }

    #[test]
    fn rrq_minimal() {
        roundtrip(Packet::Rrq {
            filename: "boot.img".into(),
            mode: Mode::Octet,
            options: OptionSet::new(),
        });
    }

    #[test]
    fn rrq_with_options() {
        let mut opts = OptionSet::new();
        opts.insert(OptionValue::BlockSize(1428));
        opts.insert(OptionValue::Timeout(3));
        opts.insert(OptionValue::TransferSize(0));
        opts.insert(OptionValue::WindowSize(8));
        roundtrip(Packet::Rrq {
            filename: "vmlinuz".into(),
            mode: Mode::Octet,
            options: opts,
        });
    }

    #[test]
    fn ack_and_data() {
        roundtrip(Packet::Ack { block: 1 });
        roundtrip(Packet::Data {
            block: 7,
            data: b"hello tftp",
        });
    }

    #[test]
    fn error_packet() {
        roundtrip(Packet::Error {
            code: ErrorCode::FileNotFound,
            msg: "not here".into(),
        });
    }

    #[test]
    fn oack_packet() {
        let mut opts = OptionSet::new();
        opts.insert(OptionValue::BlockSize(1024));
        opts.insert(OptionValue::WindowSize(4));
        roundtrip(Packet::Oack { options: opts });
    }

    #[test]
    fn rejects_unknown_opcode() {
        let bytes = [0x00, 0x09, 0x00, 0x00];
        assert!(matches!(decode(&bytes), Err(Error::UnknownOpcode(9))));
    }

    #[test]
    fn rejects_missing_nul() {
        // RRQ with filename that has no terminator.
        let bytes = [0x00, 0x01, b'f', b'o', b'o'];
        assert!(matches!(decode(&bytes), Err(Error::MissingNul)));
    }

    #[test]
    fn unknown_options_are_silently_dropped() {
        // RRQ with one known + one unknown option.
        let mut buf = BytesMut::new();
        buf.put_u16(Opcode::Rrq as u16);
        put_cstr(&mut buf, b"file");
        put_cstr(&mut buf, b"octet");
        put_cstr(&mut buf, b"blksize");
        put_cstr(&mut buf, b"1024");
        put_cstr(&mut buf, b"madeupopt");
        put_cstr(&mut buf, b"42");
        let pkt = decode(&buf).unwrap();
        match pkt {
            Packet::Rrq { options, .. } => {
                assert_eq!(options.len(), 1);
                assert_eq!(options.block_size(), Some(1024));
            }
            _ => panic!("expected RRQ"),
        }
    }

    #[test]
    fn mode_is_case_insensitive() {
        let mut buf = BytesMut::new();
        buf.put_u16(Opcode::Rrq as u16);
        put_cstr(&mut buf, b"file");
        put_cstr(&mut buf, b"OCTET");
        let pkt = decode(&buf).unwrap();
        match pkt {
            Packet::Rrq { mode, .. } => assert_eq!(mode, Mode::Octet),
            _ => panic!("expected RRQ"),
        }
    }

    #[test]
    fn rejects_blksize_out_of_range() {
        let mut buf = BytesMut::new();
        buf.put_u16(Opcode::Rrq as u16);
        put_cstr(&mut buf, b"file");
        put_cstr(&mut buf, b"octet");
        put_cstr(&mut buf, b"blksize");
        put_cstr(&mut buf, b"4");
        // Below MIN_BLOCK_SIZE — silently dropped, like an unknown option.
        let pkt = decode(&buf).unwrap();
        match pkt {
            Packet::Rrq { options, .. } => assert!(options.is_empty()),
            _ => panic!("expected RRQ"),
        }
    }
}
