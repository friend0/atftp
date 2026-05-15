use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use atftp::client::{self, Options};
use atftp::proto::Mode;

#[derive(Parser, Debug)]
#[command(
    name = "atftp",
    version,
    about = "TFTP client (Rust clone of atftp)"
)]
struct Args {
    /// Server host[:port]. Port defaults to 69 if omitted.
    server: String,

    #[command(subcommand)]
    cmd: Cmd,

    /// Transfer mode.
    #[arg(long, value_enum, default_value_t = ModeArg::Octet, global = true)]
    mode: ModeArg,

    /// Negotiate blksize (RFC 2348).
    #[arg(long, global = true)]
    blksize: Option<u16>,

    /// Negotiate per-packet timeout in seconds (RFC 2349).
    #[arg(long = "tftp-timeout", global = true)]
    tftp_timeout: Option<u8>,

    /// Negotiate windowsize (RFC 7440).
    #[arg(long, global = true)]
    windowsize: Option<u16>,

    /// Request tsize negotiation (RFC 2349). Implicitly true on `put`.
    #[arg(long, global = true)]
    tsize: bool,

    /// Number of retransmits before giving up.
    #[arg(long, default_value_t = 5, global = true)]
    retries: u32,

    /// Local-side per-packet timeout (default 5 s). Negotiated value
    /// from the server overrides this once an OACK arrives.
    #[arg(long, default_value_t = 5, global = true)]
    timeout: u8,

    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Download a file from the server.
    Get {
        /// Remote filename (path relative to server root).
        remote: String,
        /// Local destination. Defaults to the basename of `remote`.
        #[arg(short = 'l', long)]
        local: Option<PathBuf>,
    },
    /// Upload a file to the server.
    Put {
        /// Remote destination filename.
        remote: String,
        /// Local source file. Defaults to the basename of `remote`.
        #[arg(short = 'l', long)]
        local: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ModeArg {
    Octet,
    Netascii,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Octet => Mode::Octet,
            ModeArg::Netascii => Mode::NetAscii,
        }
    }
}

fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "atftp=warn",
        1 => "atftp=info",
        2 => "atftp=debug",
        _ => "atftp=trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn resolve_server(s: &str) -> anyhow::Result<SocketAddr> {
    let with_port = if s.contains(':') {
        s.to_owned()
    } else {
        format!("{s}:69")
    };
    let mut iter = with_port
        .to_socket_addrs()
        .with_context(|| format!("resolving {s}"))?;
    iter.next().ok_or_else(|| anyhow!("no addresses for {s}"))
}

fn default_local_for(remote: &str) -> PathBuf {
    PathBuf::from(remote.rsplit('/').next().unwrap_or(remote))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing(args.verbose);
    let server = resolve_server(&args.server)?;

    let mode: Mode = args.mode.into();

    match args.cmd {
        Cmd::Get { remote, local } => {
            let local = local.unwrap_or_else(|| default_local_for(&remote));
            let opts = Options {
                mode,
                blksize: args.blksize,
                timeout_secs: args.tftp_timeout,
                windowsize: args.windowsize,
                request_tsize: args.tsize,
                retries: args.retries,
                timeout: Duration::from_secs(args.timeout as u64),
            };
            let bytes = client::get(server, &remote, &local, &opts).await?;
            tracing::info!(%bytes, "get complete");
        }
        Cmd::Put { remote, local } => {
            let local = local.unwrap_or_else(|| default_local_for(&remote));
            let opts = Options {
                mode,
                blksize: args.blksize,
                timeout_secs: args.tftp_timeout,
                windowsize: args.windowsize,
                // PUT always knows the file size locally, so requesting
                // tsize is harmless and lets servers reject too-large
                // uploads up front.
                request_tsize: true,
                retries: args.retries,
                timeout: Duration::from_secs(args.timeout as u64),
            };
            let bytes = client::put(server, &remote, &local, &opts).await?;
            tracing::info!(%bytes, "put complete");
        }
    }
    Ok(())
}
