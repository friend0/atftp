//! Async TFTP client. Configure a [`Client`] (directly or via
//! [`ClientBuilder`]) and call its `get` / `put` methods. Each transfer
//! opens its own ephemeral UDP socket — the client TID per RFC 1350 §4 —
//! so a single `Client` is cheap to clone and can drive many concurrent
//! transfers to the same server.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use bytes::BytesMut;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::netascii::{FromWire, ToWire};
use crate::proto::{
    DEFAULT_BLOCK_SIZE, DEFAULT_TIMEOUT_SECS, DEFAULT_WINDOW_SIZE, ErrorCode, MAX_PACKET_SIZE,
    Mode, OptionSet, OptionValue, Packet, decode, encode_into,
};

#[derive(Clone, Debug)]
pub struct Options {
    pub mode: Mode,
    pub blksize: Option<u16>,
    pub timeout_secs: Option<u8>,
    pub windowsize: Option<u16>,
    pub request_tsize: bool,
    pub retries: u32,
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Octet,
            blksize: None,
            timeout_secs: None,
            windowsize: None,
            request_tsize: false,
            retries: 5,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS as u64),
        }
    }
}

/// Configured TFTP client targeting a single server.
#[derive(Clone, Debug)]
pub struct Client {
    server: SocketAddr,
    options: Options,
}

impl Client {
    /// Construct a client with default options.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            options: Options::default(),
        }
    }

    /// Construct a client with a pre-built [`Options`] block.
    pub fn with_options(server: SocketAddr, options: Options) -> Self {
        Self { server, options }
    }

    /// Start a builder. Equivalent to `ClientBuilder::new()`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub fn options_mut(&mut self) -> &mut Options {
        &mut self.options
    }

    /// Download `remote` from the server, writing it to `local`. Any
    /// existing file at `local` is truncated. Returns the number of
    /// bytes written to disk (post-netascii decode, if applicable).
    pub async fn get(&self, remote: &str, local: &Path) -> Result<u64> {
        let mut receiver = Receiver::new_file(local, self.options.mode).await?;
        do_get(&self.options, self.server, remote, &mut receiver).await
    }

    /// Upload `local` to the server as `remote`. Returns the number of
    /// bytes sent on the wire (post-netascii encode, if applicable).
    pub async fn put(&self, remote: &str, local: &Path) -> Result<u64> {
        let file = File::open(local).await?;
        let size = file.metadata().await?.len();
        let mut sender = Sender::new(Source::File(file), self.options.mode);
        do_put(&self.options, self.server, remote, &mut sender, Some(size)).await
    }

    /// Download `remote` and return its contents in a `Vec<u8>`.
    pub async fn get_to_vec(&self, remote: &str) -> Result<Vec<u8>> {
        let mut receiver = Receiver::new_vec(self.options.mode);
        do_get(&self.options, self.server, remote, &mut receiver).await?;
        Ok(receiver.into_vec())
    }

    /// Upload `data` to the server as `remote`.
    pub async fn put_bytes(&self, remote: &str, data: &[u8]) -> Result<u64> {
        let len = data.len() as u64;
        let mut sender = Sender::new(
            Source::Slice {
                data: data.to_vec(),
                pos: 0,
            },
            self.options.mode,
        );
        do_put(&self.options, self.server, remote, &mut sender, Some(len)).await
    }
}

/// Fluent builder for [`Client`]. Every setter returns `self`, so the
/// caller chains them and finishes with `.build(server)`.
#[derive(Clone, Debug, Default)]
pub struct ClientBuilder {
    options: Options,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mode(mut self, m: Mode) -> Self {
        self.options.mode = m;
        self
    }

    pub fn blksize(mut self, n: u16) -> Self {
        self.options.blksize = Some(n);
        self
    }

    /// Local per-packet retransmit timeout. The wire-level `timeout`
    /// option is set separately via [`Self::negotiate_timeout`].
    pub fn timeout(mut self, d: Duration) -> Self {
        self.options.timeout = d;
        self
    }

    /// Request the server use this per-packet timeout (RFC 2349).
    pub fn negotiate_timeout(mut self, secs: u8) -> Self {
        self.options.timeout_secs = Some(secs);
        self
    }

    pub fn windowsize(mut self, n: u16) -> Self {
        self.options.windowsize = Some(n);
        self
    }

    pub fn request_tsize(mut self, yes: bool) -> Self {
        self.options.request_tsize = yes;
        self
    }

    pub fn retries(mut self, n: u32) -> Self {
        self.options.retries = n;
        self
    }

    pub fn build(self, server: SocketAddr) -> Client {
        Client {
            server,
            options: self.options,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Negotiated {
    blksize: u16,
    timeout: Duration,
    windowsize: u16,
}

impl Negotiated {
    fn defaults() -> Self {
        Self {
            blksize: DEFAULT_BLOCK_SIZE,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS as u64),
            windowsize: DEFAULT_WINDOW_SIZE,
        }
    }
}

fn build_request_options(opts: &Options, tsize_for_put: Option<u64>) -> OptionSet {
    let mut set = OptionSet::new();
    if let Some(b) = opts.blksize {
        set.insert(OptionValue::BlockSize(b));
    }
    if let Some(t) = opts.timeout_secs {
        set.insert(OptionValue::Timeout(t));
    }
    if opts.request_tsize {
        // RFC 2349: client sends tsize=0 on read; server fills it in.
        // On write, client sends the actual file size.
        set.insert(OptionValue::TransferSize(tsize_for_put.unwrap_or(0)));
    }
    if let Some(w) = opts.windowsize {
        set.insert(OptionValue::WindowSize(w));
    }
    set
}

fn merge_oack(initial: Negotiated, oack: &OptionSet) -> Negotiated {
    let mut neg = initial;
    if let Some(b) = oack.block_size() {
        neg.blksize = b;
    }
    if let Some(t) = oack.timeout() {
        neg.timeout = Duration::from_secs(t as u64);
    }
    if let Some(w) = oack.window_size() {
        neg.windowsize = w;
    }
    neg
}

async fn bind_local(server: SocketAddr) -> Result<UdpSocket> {
    let bind_addr: SocketAddr = match server {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    Ok(UdpSocket::bind(bind_addr).await?)
}

async fn do_get(
    opts: &Options,
    server: SocketAddr,
    remote: &str,
    writer: &mut Receiver,
) -> Result<u64> {
    let sock = bind_local(server).await?;
    let request_options = build_request_options(opts, None);
    let request = Packet::Rrq {
        filename: remote.to_owned(),
        mode: opts.mode,
        options: request_options.clone(),
    };

    info!(%server, file = %remote, %opts.mode, "RRQ");

    let mut req_buf = BytesMut::new();
    encode_into(&request, &mut req_buf);

    let mut rxbuf = vec![0u8; MAX_PACKET_SIZE];
    let mut neg = Negotiated::defaults();
    let mut peer: Option<SocketAddr> = None;
    let want_oack = !request_options.is_empty();
    let mut first_data: Option<(u16, Vec<u8>)> = None;

    // Phase 1: send RRQ, await OACK / ACK / DATA(1).
    for attempt in 0..=opts.retries {
        sock.send_to(&req_buf, server).await?;
        let deadline = Instant::now() + opts.timeout;
        match timeout_at(deadline, sock.recv_from(&mut rxbuf)).await {
            Err(_) => {
                if attempt == opts.retries {
                    return Err(Error::Timeout(attempt));
                }
                warn!(attempt, "RRQ retransmit");
                continue;
            }
            Ok(Err(e)) => return Err(Error::Io(e)),
            Ok(Ok((n, src))) => {
                let pkt = decode(&rxbuf[..n])?;
                match pkt {
                    Packet::Oack { options } if want_oack => {
                        peer = Some(src);
                        neg = merge_oack(neg, &options);
                        send_ack(&sock, src, 0).await?;
                        break;
                    }
                    Packet::Data { block, data } => {
                        peer = Some(src);
                        // Server didn't accept any options → fall back to defaults
                        // and treat this DATA(1) as the first block.
                        first_data = Some((block, data.to_vec()));
                        break;
                    }
                    Packet::Error { code, msg } => return Err(Error::Peer { code, msg }),
                    other => debug!("ignoring unexpected initial packet: {other:?}"),
                }
            }
        }
    }

    let peer = peer.ok_or(Error::Timeout(opts.retries))?;

    let mut next_block: u16 = 1;
    let mut blocks_in_window: u16 = 0;
    let mut last_acked: u16 = 0;
    let mut finished = false;

    if let Some((block, data)) = first_data {
        if block == 1 {
            let is_final = data.len() < neg.blksize as usize;
            writer.write_block(&data).await?;
            last_acked = 1;
            next_block = 2;
            blocks_in_window = 1;
            if is_final {
                send_ack(&sock, peer, 1).await?;
                writer.finish().await?;
                return Ok(writer.bytes_written());
            }
            if blocks_in_window >= neg.windowsize {
                send_ack(&sock, peer, 1).await?;
                blocks_in_window = 0;
            }
        } else {
            return Err(Error::UnexpectedPacket);
        }
    }

    let mut attempt = 0u32;
    while !finished {
        let deadline = Instant::now() + neg.timeout;
        match recv_one(&sock, peer, deadline, &mut rxbuf).await? {
            None => {
                if attempt >= opts.retries {
                    return Err(Error::Timeout(attempt));
                }
                attempt += 1;
                warn!(attempt, "DATA timeout, re-ACK to elicit window");
                send_ack(&sock, peer, last_acked).await?;
            }
            Some(n) => match decode(&rxbuf[..n]) {
                Ok(Packet::Data { block, data }) => {
                    attempt = 0;
                    if block == next_block {
                        let is_final = data.len() < neg.blksize as usize;
                        writer.write_block(data).await?;
                        last_acked = block;
                        next_block = next_block.wrapping_add(1);
                        blocks_in_window += 1;
                        if is_final {
                            send_ack(&sock, peer, block).await?;
                            writer.finish().await?;
                            finished = true;
                        } else if blocks_in_window >= neg.windowsize {
                            send_ack(&sock, peer, block).await?;
                            blocks_in_window = 0;
                        }
                    } else {
                        debug!(got = block, expected = next_block, "out-of-order DATA");
                        send_ack(&sock, peer, last_acked).await?;
                        blocks_in_window = 0;
                    }
                }
                Ok(Packet::Error { code, msg }) => return Err(Error::Peer { code, msg }),
                Ok(other) => debug!("ignoring {other:?}"),
                Err(e) => debug!("malformed: {e}"),
            },
        }
    }

    Ok(writer.bytes_written())
}

async fn do_put(
    opts: &Options,
    server: SocketAddr,
    remote: &str,
    sender: &mut Sender,
    source_len: Option<u64>,
) -> Result<u64> {
    let sock = bind_local(server).await?;
    let request_options = build_request_options(opts, source_len);
    let request = Packet::Wrq {
        filename: remote.to_owned(),
        mode: opts.mode,
        options: request_options.clone(),
    };
    info!(%server, file = %remote, %opts.mode, "WRQ");

    let mut req_buf = BytesMut::new();
    encode_into(&request, &mut req_buf);

    let mut rxbuf = vec![0u8; MAX_PACKET_SIZE];
    let mut neg = Negotiated::defaults();
    let mut peer: Option<SocketAddr> = None;
    let want_oack = !request_options.is_empty();

    for attempt in 0..=opts.retries {
        sock.send_to(&req_buf, server).await?;
        let deadline = Instant::now() + opts.timeout;
        match timeout_at(deadline, sock.recv_from(&mut rxbuf)).await {
            Err(_) => {
                if attempt == opts.retries {
                    return Err(Error::Timeout(attempt));
                }
                warn!(attempt, "WRQ retransmit");
                continue;
            }
            Ok(Err(e)) => return Err(Error::Io(e)),
            Ok(Ok((n, src))) => {
                let pkt = decode(&rxbuf[..n])?;
                match pkt {
                    Packet::Oack { options } if want_oack => {
                        peer = Some(src);
                        neg = merge_oack(neg, &options);
                        break;
                    }
                    Packet::Ack { block: 0 } => {
                        peer = Some(src);
                        break;
                    }
                    Packet::Error { code, msg } => return Err(Error::Peer { code, msg }),
                    other => debug!("ignoring unexpected initial packet: {other:?}"),
                }
            }
        }
    }

    let peer = peer.ok_or(Error::Timeout(opts.retries))?;

    sender.set_blksize(neg.blksize as usize);

    let mut next_block: u16 = 1;
    let mut in_flight: VecDeque<(u16, Vec<u8>)> = VecDeque::new();
    let mut last_sent_short = false;
    let mut total: u64 = 0;

    loop {
        while in_flight.len() < neg.windowsize as usize && !last_sent_short {
            match sender.next_block().await? {
                Some(block) => {
                    if block.len() < neg.blksize as usize {
                        last_sent_short = true;
                    }
                    total += block.len() as u64;
                    in_flight.push_back((next_block, block));
                    next_block = next_block.wrapping_add(1);
                }
                None => break,
            }
        }
        if in_flight.is_empty() {
            return Ok(total);
        }

        let mut attempt = 0u32;
        loop {
            for (bn, data) in &in_flight {
                let mut buf = BytesMut::with_capacity(data.len() + 4);
                encode_into(
                    &Packet::Data {
                        block: *bn,
                        data,
                    },
                    &mut buf,
                );
                sock.send_to(&buf, peer).await?;
            }
            let deadline = Instant::now() + neg.timeout;
            match recv_one(&sock, peer, deadline, &mut rxbuf).await? {
                None => {
                    if attempt >= opts.retries {
                        return Err(Error::Timeout(attempt));
                    }
                    attempt += 1;
                    warn!(attempt, "DATA window retransmit");
                }
                Some(n) => match decode(&rxbuf[..n]) {
                    Ok(Packet::Ack { block }) => {
                        if consume_ack(&mut in_flight, block, neg.windowsize) {
                            if in_flight.is_empty() && last_sent_short {
                                return Ok(total);
                            }
                            break;
                        } else {
                            debug!(ack = block, "stale ACK; resend");
                        }
                    }
                    Ok(Packet::Error { code, msg }) => return Err(Error::Peer { code, msg }),
                    Ok(other) => debug!("ignoring {other:?}"),
                    Err(e) => debug!("malformed: {e}"),
                },
            }
        }
    }
}

fn consume_ack(in_flight: &mut VecDeque<(u16, Vec<u8>)>, ack: u16, windowsize: u16) -> bool {
    let mut advanced = false;
    while let Some((bn, _)) = in_flight.front() {
        let bn = *bn;
        if bn == ack {
            in_flight.pop_front();
            advanced = true;
            break;
        }
        let diff = ack.wrapping_sub(bn);
        if diff > 0 && diff < windowsize {
            in_flight.pop_front();
            advanced = true;
        } else {
            break;
        }
    }
    advanced
}

async fn send_ack(sock: &UdpSocket, peer: SocketAddr, block: u16) -> Result<()> {
    let mut buf = BytesMut::new();
    encode_into(&Packet::Ack { block }, &mut buf);
    sock.send_to(&buf, peer).await?;
    Ok(())
}

async fn recv_one(
    sock: &UdpSocket,
    expected: SocketAddr,
    deadline: Instant,
    buf: &mut [u8],
) -> Result<Option<usize>> {
    loop {
        match timeout_at(deadline, sock.recv_from(buf)).await {
            Err(_) => return Ok(None),
            Ok(Err(e)) => return Err(Error::Io(e)),
            Ok(Ok((n, src))) => {
                if src != expected {
                    let mut err_buf = BytesMut::new();
                    encode_into(
                        &Packet::Error {
                            code: ErrorCode::UnknownTid,
                            msg: "unknown transfer id".into(),
                        },
                        &mut err_buf,
                    );
                    let _ = sock.send_to(&err_buf, src).await;
                    continue;
                }
                return Ok(Some(n));
            }
        }
    }
}

/// Source of bytes for a `put`. The Slice variant copies once at
/// construction so the future is `'static` regardless of the caller's
/// borrow lifetime.
enum Source {
    File(File),
    Slice { data: Vec<u8>, pos: usize },
}

struct Sender {
    source: Source,
    encoder: Option<ToWire>,
    pending: Vec<u8>,
    blksize: usize,
    eof: bool,
    final_emitted: bool,
}

impl Sender {
    fn new(source: Source, mode: Mode) -> Self {
        Self {
            source,
            encoder: matches!(mode, Mode::NetAscii).then(ToWire::new),
            pending: Vec::new(),
            // Set later via set_blksize once the OACK/ACK has settled
            // the negotiated value.
            blksize: 0,
            eof: false,
            final_emitted: false,
        }
    }

    fn set_blksize(&mut self, blksize: usize) {
        self.blksize = blksize;
        self.pending.reserve(blksize * 2);
    }

    async fn read_chunk(&mut self, chunk: &mut [u8]) -> Result<usize> {
        match &mut self.source {
            Source::File(f) => Ok(f.read(chunk).await?),
            Source::Slice { data, pos } => {
                let remaining = &data[*pos..];
                let n = remaining.len().min(chunk.len());
                chunk[..n].copy_from_slice(&remaining[..n]);
                *pos += n;
                Ok(n)
            }
        }
    }

    async fn next_block(&mut self) -> Result<Option<Vec<u8>>> {
        if self.final_emitted {
            return Ok(None);
        }
        let mut chunk = vec![0u8; self.blksize];
        while self.pending.len() < self.blksize && !self.eof {
            let n = self.read_chunk(&mut chunk).await?;
            if n == 0 {
                self.eof = true;
                break;
            }
            match &mut self.encoder {
                Some(enc) => {
                    enc.translate(&chunk[..n], &mut self.pending);
                }
                None => self.pending.extend_from_slice(&chunk[..n]),
            }
        }
        if self.pending.is_empty() && self.eof {
            self.final_emitted = true;
            return Ok(Some(Vec::new()));
        }
        let take = self.pending.len().min(self.blksize);
        let block: Vec<u8> = self.pending.drain(..take).collect();
        if block.len() < self.blksize {
            self.final_emitted = true;
        }
        Ok(Some(block))
    }
}

/// Destination for received bytes.
enum Sink {
    File(File),
    Vec(Vec<u8>),
}

struct Receiver {
    sink: Sink,
    decoder: Option<FromWire>,
    bytes: u64,
}

impl Receiver {
    async fn new_file(local: &Path, mode: Mode) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(local)
            .await?;
        Ok(Self {
            sink: Sink::File(file),
            decoder: matches!(mode, Mode::NetAscii).then(FromWire::new),
            bytes: 0,
        })
    }

    fn new_vec(mode: Mode) -> Self {
        Self {
            sink: Sink::Vec(Vec::new()),
            decoder: matches!(mode, Mode::NetAscii).then(FromWire::new),
            bytes: 0,
        }
    }

    async fn write_block(&mut self, data: &[u8]) -> Result<()> {
        if let Some(d) = &mut self.decoder {
            let mut out = Vec::with_capacity(data.len());
            d.translate(data, &mut out);
            self.write_raw(&out).await
        } else {
            self.write_raw(data).await
        }
    }

    async fn write_raw(&mut self, buf: &[u8]) -> Result<()> {
        match &mut self.sink {
            Sink::File(f) => f.write_all(buf).await?,
            Sink::Vec(v) => v.extend_from_slice(buf),
        }
        self.bytes += buf.len() as u64;
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        if let Some(d) = &mut self.decoder {
            let mut tail = Vec::new();
            d.finish(&mut tail);
            if !tail.is_empty() {
                self.write_raw(&tail).await?;
            }
        }
        if let Sink::File(f) = &mut self.sink {
            f.flush().await?;
        }
        Ok(())
    }

    fn bytes_written(&self) -> u64 {
        self.bytes
    }

    fn into_vec(self) -> Vec<u8> {
        match self.sink {
            Sink::Vec(v) => v,
            Sink::File(_) => unreachable!("into_vec called on file-backed Receiver"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn build_request_options_round_trip() {
        let opts = Options {
            blksize: Some(1024),
            timeout_secs: Some(3),
            request_tsize: true,
            windowsize: Some(8),
            ..Options::default()
        };
        let set = build_request_options(&opts, None);
        assert_eq!(set.block_size(), Some(1024));
        assert_eq!(set.timeout(), Some(3));
        assert_eq!(set.transfer_size(), Some(0));
        assert_eq!(set.window_size(), Some(8));
    }

    #[test]
    fn merge_oack_overrides_only_provided() {
        let initial = Negotiated::defaults();
        let mut oack = OptionSet::new();
        oack.insert(OptionValue::BlockSize(1428));
        let merged = merge_oack(initial, &oack);
        assert_eq!(merged.blksize, 1428);
        assert_eq!(merged.windowsize, DEFAULT_WINDOW_SIZE);
    }

    #[test]
    fn builder_defaults_match_options_default() {
        let client = Client::builder().build(addr());
        let defaults = Options::default();
        assert_eq!(client.options().mode, defaults.mode);
        assert_eq!(client.options().blksize, defaults.blksize);
        assert_eq!(client.options().timeout_secs, defaults.timeout_secs);
        assert_eq!(client.options().windowsize, defaults.windowsize);
        assert_eq!(client.options().request_tsize, defaults.request_tsize);
        assert_eq!(client.options().retries, defaults.retries);
        assert_eq!(client.options().timeout, defaults.timeout);
    }

    #[test]
    fn builder_setters_wire_through() {
        let client = Client::builder()
            .mode(Mode::NetAscii)
            .blksize(1428)
            .negotiate_timeout(7)
            .windowsize(16)
            .request_tsize(true)
            .retries(10)
            .timeout(Duration::from_millis(250))
            .build(addr());
        let o = client.options();
        assert_eq!(o.mode, Mode::NetAscii);
        assert_eq!(o.blksize, Some(1428));
        assert_eq!(o.timeout_secs, Some(7));
        assert_eq!(o.windowsize, Some(16));
        assert!(o.request_tsize);
        assert_eq!(o.retries, 10);
        assert_eq!(o.timeout, Duration::from_millis(250));
    }

    #[test]
    fn options_mut_allows_post_construction_edit() {
        let mut client = Client::new(addr());
        client.options_mut().blksize = Some(8192);
        assert_eq!(client.options().blksize, Some(8192));
    }

    #[test]
    fn with_options_preserves_caller_struct() {
        let opts = Options {
            blksize: Some(512),
            ..Options::default()
        };
        let client = Client::with_options(addr(), opts);
        assert_eq!(client.options().blksize, Some(512));
    }
}
