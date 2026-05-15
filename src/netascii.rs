//! Streaming netascii translation (RFC 764, RFC 1350 §2).
//!
//! On the wire: ASCII text using CR LF as a line terminator. A literal
//! CR is encoded as CR NUL.
//!
//! On Unix disk: lines are terminated by LF; CR appears verbatim.
//!
//! Translation must be streaming because TFTP block boundaries can fall
//! between the two bytes of a CR LF (or CR NUL) pair, so each translator
//! holds a single byte of carry state across calls.

/// Disk -> wire encoder for RRQ (server reading file, client put).
#[derive(Default, Debug)]
pub struct ToWire {
    /// True if the previous byte we *emitted* was an unmatched CR
    /// from the source — irrelevant. Instead this carries: "do we
    /// owe an emission because the last call ended mid-translation?"
    /// We keep it simple: no carry needed for to-wire because each
    /// input byte produces 1-2 output bytes immediately.
    _phantom: (),
}

impl ToWire {
    pub fn new() -> Self {
        Self::default()
    }

    /// Translate `input` into `out`. Returns the number of source bytes
    /// consumed (always `input.len()`).
    pub fn translate(&mut self, input: &[u8], out: &mut Vec<u8>) -> usize {
        for &b in input {
            match b {
                b'\n' => {
                    out.push(b'\r');
                    out.push(b'\n');
                }
                b'\r' => {
                    out.push(b'\r');
                    out.push(0);
                }
                _ => out.push(b),
            }
        }
        input.len()
    }
}

/// Wire -> disk decoder for WRQ (server receiving) / client get.
#[derive(Default, Debug)]
pub struct FromWire {
    /// If the previous block ended with a CR, we must look at the
    /// first byte of the next block to decide whether to emit CR
    /// (followed by LF -> emit LF; followed by NUL -> emit CR;
    /// followed by anything else -> emit CR + that byte verbatim,
    /// which is technically malformed but tolerant).
    pending_cr: bool,
}

impl FromWire {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn translate(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &b in input {
            if self.pending_cr {
                self.pending_cr = false;
                match b {
                    b'\n' => out.push(b'\n'),
                    0 => out.push(b'\r'),
                    other => {
                        out.push(b'\r');
                        out.push(other);
                    }
                }
            } else if b == b'\r' {
                self.pending_cr = true;
            } else {
                out.push(b);
            }
        }
    }

    /// Call once at end of stream — flushes a trailing CR (which is
    /// technically a protocol violation, but we tolerate it).
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if self.pending_cr {
            self.pending_cr = false;
            out.push(b'\r');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_wire(s: &[u8]) -> Vec<u8> {
        let mut e = ToWire::new();
        let mut out = Vec::new();
        e.translate(s, &mut out);
        out
    }

    fn from_wire(chunks: &[&[u8]]) -> Vec<u8> {
        let mut d = FromWire::new();
        let mut out = Vec::new();
        for c in chunks {
            d.translate(c, &mut out);
        }
        d.finish(&mut out);
        out
    }

    #[test]
    fn lf_becomes_crlf() {
        assert_eq!(to_wire(b"a\nb\n"), b"a\r\nb\r\n");
    }

    #[test]
    fn cr_becomes_cr_nul() {
        assert_eq!(to_wire(b"a\rb"), b"a\r\0b");
    }

    #[test]
    fn crlf_becomes_lf() {
        assert_eq!(from_wire(&[b"a\r\nb\r\n"]), b"a\nb\n");
    }

    #[test]
    fn cr_nul_becomes_cr() {
        assert_eq!(from_wire(&[b"a\r\0b"]), b"a\rb");
    }

    #[test]
    fn split_across_blocks() {
        // CR at end of one chunk, LF at start of next.
        assert_eq!(from_wire(&[b"abc\r", b"\ndef"]), b"abc\ndef");
        // CR at end of one chunk, NUL at start of next.
        assert_eq!(from_wire(&[b"abc\r", b"\0def"]), b"abc\rdef");
    }
}
