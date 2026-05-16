use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use aitftp::client::Client;
use aitftp::proto::Mode;

#[derive(Parser, Debug)]
#[command(name = "aitftp", version, about = "TFTP client (Rust clone of atftp)")]
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
        0 => "aitftp=warn",
        1 => "aitftp=info",
        2 => "aitftp=debug",
        _ => "aitftp=trace",
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

    // PUT always knows the source size locally, so tsize negotiation is
    // free and lets servers reject oversized uploads up front.
    let want_tsize = args.tsize || matches!(args.cmd, Cmd::Put { .. });

    let mut builder = Client::builder()
        .mode(args.mode.into())
        .retries(args.retries)
        .timeout(Duration::from_secs(args.timeout as u64))
        .request_tsize(want_tsize);
    if let Some(n) = args.blksize {
        builder = builder.blksize(n);
    }
    if let Some(n) = args.tftp_timeout {
        builder = builder.negotiate_timeout(n);
    }
    if let Some(n) = args.windowsize {
        builder = builder.windowsize(n);
    }
    let client = builder.build(server);

    match args.cmd {
        Cmd::Get { remote, local } => {
            let local = local.unwrap_or_else(|| default_local_for(&remote));
            let bytes = client.get(&remote, &local).await?;
            tracing::info!(%bytes, "get complete");
        }
        Cmd::Put { remote, local } => {
            let local = local.unwrap_or_else(|| default_local_for(&remote));
            let bytes = client.put(&remote, &local).await?;
            tracing::info!(%bytes, "put complete");
        }
    }
    Ok(())
}
