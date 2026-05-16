//! Async TFTP server. One UDP listener accepts RRQ/WRQ; each transfer
//! runs in its own tokio task on a fresh ephemeral socket (the "TID"
//! per RFC 1350 §4).
//!
//! Library users configure a [`Server`] via [`Server::builder`], call
//! [`ServerBuilder::bind`] to claim the listening socket and resolve
//! the root directory, then drive it with [`Server::run`] or
//! [`Server::run_until`] for graceful shutdown.

use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};
use crate::netascii::{FromWire, ToWire};
use crate::path_safe;
use crate::proto::{
    DEFAULT_BLOCK_SIZE, DEFAULT_TIMEOUT_SECS, DEFAULT_WINDOW_SIZE, ErrorCode, MAX_BLOCK_SIZE,
    MAX_PACKET_SIZE, MIN_BLOCK_SIZE, Mode, OptionSet, OptionValue, Packet, decode, encode_into,
};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub root: PathBuf,
    pub allow_overwrite: bool,
    pub timeout: Duration,
    pub retries: u32,
    pub max_block_size: u16,
    pub allow_windowsize: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:69".parse().unwrap(),
            root: PathBuf::from("."),
            allow_overwrite: false,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS as u64),
            retries: 5,
            max_block_size: MAX_BLOCK_SIZE,
            allow_windowsize: true,
        }
    }
}

/// Fluent builder for [`Server`]. The terminal `bind()` call performs
/// the canonical-root resolution and the UDP socket bind, so any
/// configuration error surfaces before `run` starts.
#[derive(Clone, Debug, Default)]
pub struct ServerBuilder {
    cfg: Config,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.cfg.listen = addr;
        self
    }

    pub fn root(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.root = path.into();
        self
    }

    pub fn allow_overwrite(mut self, yes: bool) -> Self {
        self.cfg.allow_overwrite = yes;
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.cfg.timeout = d;
        self
    }

    pub fn retries(mut self, n: u32) -> Self {
        self.cfg.retries = n;
        self
    }

    pub fn max_block_size(mut self, n: u16) -> Self {
        self.cfg.max_block_size = n;
        self
    }

    pub fn allow_windowsize(mut self, yes: bool) -> Self {
        self.cfg.allow_windowsize = yes;
        self
    }

    /// Canonicalize the root and bind the listening UDP socket.
    pub async fn bind(self) -> Result<Server> {
        Server::bind(self.cfg).await
    }
}

/// A bound, ready-to-run TFTP server.
pub struct Server {
    cfg: Arc<Config>,
    listener: UdpSocket,
    local_addr: SocketAddr,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Take a pre-built [`Config`], canonicalize its root, and bind its
    /// listening socket. Returns a [`Server`] from which the actually
    /// bound address can be inspected before `run` begins.
    pub async fn bind(cfg: Config) -> Result<Self> {
        let canon_root = tokio::fs::canonicalize(&cfg.root)
            .await
            .map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("root: {e}"))))?;
        let cfg = Config {
            root: canon_root,
            ..cfg
        };
        let listener = UdpSocket::bind(cfg.listen).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            cfg: Arc::new(cfg),
            listener,
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn root(&self) -> &Path {
        &self.cfg.root
    }

    /// Accept transfers forever (or until an I/O error on the listener).
    /// Each accepted request is handled on a dedicated tokio task.
    pub async fn run(self) -> Result<()> {
        info!(
            listen = %self.local_addr,
            root = %self.cfg.root.display(),
            "aitftpd listening"
        );
        let listener = self.listener;
        let cfg = self.cfg;
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        loop {
            let (n, peer) = listener.recv_from(&mut buf).await?;
            let cfg2 = cfg.clone();
            let frame = buf[..n].to_vec();
            tokio::spawn(async move {
                if let Err(e) = handle_initial(cfg2, peer, frame).await {
                    error!(%peer, "transfer failed: {e}");
                }
            });
        }
    }

    /// Run the server, stopping cleanly when `shutdown` resolves.
    /// In-flight transfers detach and keep their own sockets, so they
    /// will continue to completion after the listener stops accepting.
    pub async fn run_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future,
    {
        tokio::select! {
            r = self.run() => r,
            _ = shutdown => {
                info!("shutdown signalled");
                Ok(())
            }
        }
    }
}

async fn handle_initial(cfg: Arc<Config>, peer: SocketAddr, frame: Vec<u8>) -> Result<()> {
    let packet = match decode(&frame) {
        Ok(p) => p,
        Err(e) => {
            warn!(%peer, "bad initial packet: {e}");
            return Ok(());
        }
    };
    // The per-transfer socket binds to an OS-assigned port (the server
    // TID), addr family inherited from the listener.
    let bind_addr: SocketAddr = match cfg.listen {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    debug!(%peer, local = %sock.local_addr()?, "spawned transfer");

    match packet {
        Packet::Rrq {
            filename,
            mode,
            options,
        } => serve_rrq(cfg, sock, peer, filename, mode, options).await,
        Packet::Wrq {
            filename,
            mode,
            options,
        } => serve_wrq(cfg, sock, peer, filename, mode, options).await,
        other => {
            warn!(%peer, "ignoring non-request initial packet: {other:?}");
            Ok(())
        }
    }
}

/// Negotiated transfer parameters.
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

/// Build the OACK option set we will accept and the resulting
/// negotiated parameters. Options the client didn't request remain at
/// defaults.
fn negotiate(
    cfg: &Config,
    requested: &OptionSet,
    file_size_for_tsize: Option<u64>,
) -> (OptionSet, Negotiated) {
    let mut out = OptionSet::new();
    let mut neg = Negotiated::defaults();

    if let Some(b) = requested.block_size() {
        let chosen = b.clamp(MIN_BLOCK_SIZE, cfg.max_block_size);
        neg.blksize = chosen;
        out.insert(OptionValue::BlockSize(chosen));
    }
    if let Some(t) = requested.timeout() {
        let chosen = t.max(1);
        neg.timeout = Duration::from_secs(chosen as u64);
        out.insert(OptionValue::Timeout(chosen));
    }
    if requested.transfer_size().is_some() {
        // RFC 2349: on a read request, the client sends tsize=0; the
        // server fills in the actual file size.
        if let Some(sz) = file_size_for_tsize {
            out.insert(OptionValue::TransferSize(sz));
        } else {
            // Write request — client tells us the size; we just echo it.
            out.insert(OptionValue::TransferSize(requested.transfer_size().unwrap()));
        }
    }
    if let Some(w) = requested.window_size() {
        if cfg.allow_windowsize {
            let chosen = w.max(1);
            neg.windowsize = chosen;
            out.insert(OptionValue::WindowSize(chosen));
        }
    }
    (out, neg)
}

/// Send an ERROR packet (best-effort — we ignore send failures because
/// the connection is already on its way out).
async fn send_error(sock: &UdpSocket, peer: SocketAddr, code: ErrorCode, msg: &str) {
    let mut buf = BytesMut::with_capacity(4 + msg.len() + 1);
    encode_into(
        &Packet::Error {
            code,
            msg: msg.to_owned(),
        },
        &mut buf,
    );
    let _ = sock.send_to(&buf, peer).await;
}

async fn map_io_to_error(sock: &UdpSocket, peer: SocketAddr, err: std::io::Error) -> Error {
    use std::io::ErrorKind;
    let (code, msg): (ErrorCode, &str) = match err.kind() {
        ErrorKind::NotFound => (ErrorCode::FileNotFound, "file not found"),
        ErrorKind::PermissionDenied => (ErrorCode::AccessViolation, "access violation"),
        ErrorKind::AlreadyExists => (ErrorCode::FileExists, "file already exists"),
        _ => (ErrorCode::NotDefined, "i/o error"),
    };
    send_error(sock, peer, code, msg).await;
    Error::Io(err)
}

/// RRQ — server is the data sender.
async fn serve_rrq(
    cfg: Arc<Config>,
    sock: UdpSocket,
    peer: SocketAddr,
    filename: String,
    mode: Mode,
    options: OptionSet,
) -> Result<()> {
    let path = match path_safe::resolve(&cfg.root, &filename) {
        Ok(p) => p,
        Err(e) => {
            send_error(&sock, peer, ErrorCode::AccessViolation, "access violation").await;
            return Err(e);
        }
    };
    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(e) => return Err(map_io_to_error(&sock, peer, e).await),
    };
    let metadata = file.metadata().await?;
    let file_size = metadata.len();

    let (oack, neg) = negotiate(&cfg, &options, Some(file_size));
    let want_oack = !oack.is_empty();

    info!(
        %peer, file = %path.display(), %mode, blksize = neg.blksize,
        windowsize = neg.windowsize, timeout = ?neg.timeout, oack = want_oack,
        "RRQ"
    );

    let mut sender = RrqSender {
        sock: &sock,
        peer,
        cfg: &cfg,
        neg,
        file,
        encoder: matches!(mode, Mode::NetAscii).then(ToWire::new),
        pending: Vec::with_capacity(neg.blksize as usize * 2),
        eof: false,
        in_flight: VecDeque::new(),
        next_block: 1,
        last_sent_short: false,
    };

    if want_oack {
        sender.send_oack_and_wait_ack0(&oack).await?;
    }
    sender.run().await
}

struct RrqSender<'a> {
    sock: &'a UdpSocket,
    peer: SocketAddr,
    cfg: &'a Config,
    neg: Negotiated,
    file: File,
    encoder: Option<ToWire>,
    pending: Vec<u8>,
    eof: bool,
    in_flight: VecDeque<(u16, Vec<u8>)>,
    next_block: u16,
    last_sent_short: bool,
}

impl<'a> RrqSender<'a> {
    async fn send_oack_and_wait_ack0(&mut self, oack: &OptionSet) -> Result<()> {
        let mut buf = BytesMut::new();
        encode_into(
            &Packet::Oack {
                options: oack.clone(),
            },
            &mut buf,
        );
        let mut rxbuf = vec![0u8; MAX_PACKET_SIZE];
        for attempt in 0..=self.cfg.retries {
            self.sock.send_to(&buf, self.peer).await?;
            let deadline = Instant::now() + self.neg.timeout;
            match recv_one(self.sock, self.peer, deadline, &mut rxbuf).await? {
                None => {
                    if attempt == self.cfg.retries {
                        return Err(Error::Timeout(attempt));
                    }
                    warn!(%self.peer, attempt, "OACK retransmit");
                }
                Some(n) => match decode(&rxbuf[..n]) {
                    Ok(Packet::Ack { block: 0 }) => return Ok(()),
                    Ok(Packet::Error { code, msg }) => return Err(Error::Peer { code, msg }),
                    Ok(other) => {
                        debug!(%self.peer, "discarding {:?} while awaiting ACK(0)", other)
                    }
                    Err(e) => debug!(%self.peer, "malformed: {e}"),
                },
            }
        }
        Err(Error::Timeout(self.cfg.retries))
    }

    /// Read enough bytes from the file (with optional netascii encoding)
    /// to produce one block of `blksize` bytes, or return a short block
    /// if EOF is reached.
    async fn read_one_block(&mut self) -> Result<Option<Vec<u8>>> {
        let blksize = self.neg.blksize as usize;
        // We've already shipped the final short block — nothing more to do.
        if self.last_sent_short {
            return Ok(None);
        }
        // Fill `pending` with at least blksize bytes (or until EOF).
        let mut chunk = vec![0u8; blksize];
        while self.pending.len() < blksize && !self.eof {
            let n = self.file.read(&mut chunk).await?;
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
            // File length aligned exactly with a block boundary on the
            // *previous* iteration; emit a final empty block so the
            // receiver knows the transfer is complete (RFC 1350).
            self.last_sent_short = true;
            return Ok(Some(Vec::new()));
        }

        let take = self.pending.len().min(blksize);
        let block: Vec<u8> = self.pending.drain(..take).collect();
        if block.len() < blksize {
            self.last_sent_short = true;
        }
        Ok(Some(block))
    }

    async fn fill_window(&mut self) -> Result<()> {
        while self.in_flight.len() < self.neg.windowsize as usize {
            match self.read_one_block().await? {
                Some(block) => {
                    let bn = self.next_block;
                    self.in_flight.push_back((bn, block));
                    // Wrap to 0 on overflow (atftp convention; matches PXE).
                    self.next_block = self.next_block.wrapping_add(1);
                }
                None => break,
            }
        }
        Ok(())
    }

    async fn send_window(&self) -> Result<()> {
        let mut buf = BytesMut::with_capacity(self.neg.blksize as usize + 4);
        for (bn, data) in &self.in_flight {
            buf.clear();
            encode_into(
                &Packet::Data {
                    block: *bn,
                    data: data,
                },
                &mut buf,
            );
            self.sock.send_to(&buf, self.peer).await?;
        }
        Ok(())
    }

    async fn run(&mut self) -> Result<()> {
        let mut rxbuf = vec![0u8; MAX_PACKET_SIZE];
        loop {
            self.fill_window().await?;
            if self.in_flight.is_empty() {
                return Ok(());
            }
            let mut attempt = 0u32;
            loop {
                self.send_window().await?;
                let deadline = Instant::now() + self.neg.timeout;
                match recv_one(self.sock, self.peer, deadline, &mut rxbuf).await? {
                    None => {
                        if attempt >= self.cfg.retries {
                            send_error(self.sock, self.peer, ErrorCode::NotDefined, "timed out")
                                .await;
                            return Err(Error::Timeout(attempt));
                        }
                        attempt += 1;
                        warn!(%self.peer, attempt, "DATA window retransmit");
                    }
                    Some(n) => match decode(&rxbuf[..n]) {
                        Ok(Packet::Ack { block }) => {
                            if self.consume_ack(block) {
                                break;
                            } else {
                                debug!(%self.peer, ack = block, "stale ACK; resend");
                            }
                        }
                        Ok(Packet::Error { code, msg }) => {
                            return Err(Error::Peer { code, msg });
                        }
                        Ok(other) => debug!(%self.peer, "ignoring {:?} during DATA", other),
                        Err(e) => debug!(%self.peer, "malformed: {e}"),
                    },
                }
            }
        }
    }

    /// Returns true if the ACK was within the in-flight window and we
    /// can advance / refill. The transfer terminates when the ACK
    /// covers the final short block.
    fn consume_ack(&mut self, ack: u16) -> bool {
        let mut advanced = false;
        while let Some((bn, _)) = self.in_flight.front() {
            if *bn == ack {
                self.in_flight.pop_front();
                advanced = true;
                break;
            }
            // Cumulative ACK covers earlier blocks too.
            if u16_le_in_window(*bn, ack, self.neg.windowsize) {
                self.in_flight.pop_front();
                advanced = true;
            } else {
                break;
            }
        }
        if advanced && self.in_flight.is_empty() && self.last_sent_short {
            // Final block ACKed — done. Signal completion to caller via
            // empty in_flight + last_sent_short, which fill_window will
            // observe as "nothing more to do".
            return true;
        }
        advanced
    }
}

/// True if `bn` is between (ack - windowsize, ack] in u16 modular
/// arithmetic — i.e., `bn` came earlier than `ack` within the window.
fn u16_le_in_window(bn: u16, ack: u16, windowsize: u16) -> bool {
    let diff = ack.wrapping_sub(bn);
    diff > 0 && diff < windowsize
}

/// WRQ — server is the data receiver.
async fn serve_wrq(
    cfg: Arc<Config>,
    sock: UdpSocket,
    peer: SocketAddr,
    filename: String,
    mode: Mode,
    options: OptionSet,
) -> Result<()> {
    let path = match path_safe::resolve(&cfg.root, &filename) {
        Ok(p) => p,
        Err(e) => {
            send_error(&sock, peer, ErrorCode::AccessViolation, "access violation").await;
            return Err(e);
        }
    };

    let mut open = OpenOptions::new();
    open.write(true).create(true);
    if !cfg.allow_overwrite {
        open.create_new(true);
    } else {
        open.truncate(true);
    }
    let file = match open.open(&path).await {
        Ok(f) => f,
        Err(e) => return Err(map_io_to_error(&sock, peer, e).await),
    };

    let (oack, neg) = negotiate(&cfg, &options, None);
    let want_oack = !oack.is_empty();

    info!(
        %peer, file = %path.display(), %mode, blksize = neg.blksize,
        windowsize = neg.windowsize, timeout = ?neg.timeout, oack = want_oack,
        "WRQ"
    );

    let mut recv = WrqReceiver {
        sock: &sock,
        peer,
        cfg: &cfg,
        neg,
        file,
        decoder: matches!(mode, Mode::NetAscii).then(FromWire::new),
        next_block: 1,
        blocks_in_window: 0,
        last_acked: 0,
        finished: false,
    };

    if want_oack {
        recv.send_initial_oack(&oack).await?;
    } else {
        // Classic ACK(0) signals "ready, send DATA(1)".
        recv.send_ack(0).await?;
    }
    recv.run().await
}

struct WrqReceiver<'a> {
    sock: &'a UdpSocket,
    peer: SocketAddr,
    cfg: &'a Config,
    neg: Negotiated,
    file: File,
    decoder: Option<FromWire>,
    /// Next block number we expect.
    next_block: u16,
    /// Count of blocks accepted since last ACK (windowsize tracking).
    blocks_in_window: u16,
    /// Highest block we've cumulatively ACKed.
    last_acked: u16,
    finished: bool,
}

impl<'a> WrqReceiver<'a> {
    async fn send_ack(&self, block: u16) -> Result<()> {
        let mut buf = BytesMut::new();
        encode_into(&Packet::Ack { block }, &mut buf);
        self.sock.send_to(&buf, self.peer).await?;
        Ok(())
    }

    async fn send_initial_oack(&self, oack: &OptionSet) -> Result<()> {
        let mut buf = BytesMut::new();
        encode_into(
            &Packet::Oack {
                options: oack.clone(),
            },
            &mut buf,
        );
        self.sock.send_to(&buf, self.peer).await?;
        Ok(())
    }

    async fn run(&mut self) -> Result<()> {
        let mut attempt = 0u32;
        let mut rxbuf = vec![0u8; MAX_PACKET_SIZE];
        while !self.finished {
            let deadline = Instant::now() + self.neg.timeout;
            match recv_one(self.sock, self.peer, deadline, &mut rxbuf).await? {
                None => {
                    if attempt >= self.cfg.retries {
                        send_error(self.sock, self.peer, ErrorCode::NotDefined, "timed out")
                            .await;
                        return Err(Error::Timeout(attempt));
                    }
                    attempt += 1;
                    warn!(%self.peer, attempt, "WRQ ACK retransmit");
                    self.send_ack(self.last_acked).await?;
                }
                Some(n) => match decode(&rxbuf[..n]) {
                    Ok(Packet::Data { block, data }) => {
                        attempt = 0;
                        if block == self.next_block {
                            let is_final = data.len() < self.neg.blksize as usize;
                            self.write_block(data).await?;
                            self.last_acked = block;
                            self.next_block = self.next_block.wrapping_add(1);
                            self.blocks_in_window += 1;
                            if is_final {
                                if let Some(d) = &mut self.decoder {
                                    let mut tail = Vec::new();
                                    d.finish(&mut tail);
                                    if !tail.is_empty() {
                                        self.file.write_all(&tail).await?;
                                    }
                                }
                                self.file.flush().await?;
                                self.send_ack(block).await?;
                                self.finished = true;
                            } else if self.blocks_in_window >= self.neg.windowsize {
                                self.send_ack(block).await?;
                                self.blocks_in_window = 0;
                            }
                        } else {
                            debug!(%self.peer, got = block, expected = self.next_block, "out-of-order DATA");
                            self.send_ack(self.last_acked).await?;
                            self.blocks_in_window = 0;
                        }
                    }
                    Ok(Packet::Error { code, msg }) => return Err(Error::Peer { code, msg }),
                    Ok(other) => debug!(%self.peer, "ignoring {:?} during WRQ", other),
                    Err(e) => debug!(%self.peer, "malformed: {e}"),
                },
            }
        }
        Ok(())
    }

    async fn write_block(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.decoder {
            Some(dec) => {
                let mut out = Vec::with_capacity(data.len());
                dec.translate(data, &mut out);
                self.file.write_all(&out).await?;
            }
            None => {
                self.file.write_all(data).await?;
            }
        }
        Ok(())
    }
}

/// Receive one packet from the bound socket before `deadline`. Packets
/// from peers other than `expected` are answered with ERROR(UnknownTid)
/// and otherwise discarded (RFC 1350 §4). Returns `None` on timeout.
/// The caller owns `buf` and can `decode(&buf[..n])` after a `Some(n)`
/// return.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_clamps_blksize() {
        let cfg = Config {
            max_block_size: 1024,
            ..Config::default()
        };
        let mut req = OptionSet::new();
        req.insert(OptionValue::BlockSize(8000));
        let (oack, neg) = negotiate(&cfg, &req, Some(0));
        assert_eq!(neg.blksize, 1024);
        assert_eq!(oack.block_size(), Some(1024));
    }

    #[test]
    fn negotiate_fills_tsize_for_read() {
        let cfg = Config::default();
        let mut req = OptionSet::new();
        req.insert(OptionValue::TransferSize(0));
        let (oack, _) = negotiate(&cfg, &req, Some(12345));
        assert_eq!(oack.transfer_size(), Some(12345));
    }

    #[test]
    fn negotiate_drops_windowsize_when_disabled() {
        let cfg = Config {
            allow_windowsize: false,
            ..Config::default()
        };
        let mut req = OptionSet::new();
        req.insert(OptionValue::WindowSize(8));
        let (oack, neg) = negotiate(&cfg, &req, Some(0));
        assert_eq!(oack.window_size(), None);
        assert_eq!(neg.windowsize, DEFAULT_WINDOW_SIZE);
    }

    #[test]
    fn cumulative_ack_window() {
        // bn=5, ack=7, windowsize=4 — bn is in (3, 7], so true.
        assert!(u16_le_in_window(5, 7, 4));
        // bn=2 with ack=7, windowsize=4 — 2 is below window.
        assert!(!u16_le_in_window(2, 7, 4));
        // Wrap: bn=65535, ack=2, windowsize=4 — diff = 3, true.
        assert!(u16_le_in_window(65535, 2, 4));
    }

    #[test]
    fn builder_defaults_match_config_default() {
        let cfg_via_builder = ServerBuilder::new().cfg;
        let defaults = Config::default();
        assert_eq!(cfg_via_builder.listen, defaults.listen);
        assert_eq!(cfg_via_builder.root, defaults.root);
        assert_eq!(cfg_via_builder.allow_overwrite, defaults.allow_overwrite);
        assert_eq!(cfg_via_builder.timeout, defaults.timeout);
        assert_eq!(cfg_via_builder.retries, defaults.retries);
        assert_eq!(cfg_via_builder.max_block_size, defaults.max_block_size);
        assert_eq!(cfg_via_builder.allow_windowsize, defaults.allow_windowsize);
    }

    #[test]
    fn builder_setters_wire_through() {
        let addr: SocketAddr = "127.0.0.1:6970".parse().unwrap();
        let cfg = ServerBuilder::new()
            .listen(addr)
            .root("/tmp/something")
            .allow_overwrite(true)
            .timeout(Duration::from_millis(250))
            .retries(11)
            .max_block_size(1024)
            .allow_windowsize(false)
            .cfg;
        assert_eq!(cfg.listen, addr);
        assert_eq!(cfg.root, PathBuf::from("/tmp/something"));
        assert!(cfg.allow_overwrite);
        assert_eq!(cfg.timeout, Duration::from_millis(250));
        assert_eq!(cfg.retries, 11);
        assert_eq!(cfg.max_block_size, 1024);
        assert!(!cfg.allow_windowsize);
    }
}
