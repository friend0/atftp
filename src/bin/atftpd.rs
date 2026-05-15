use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use atftp::proto::MAX_BLOCK_SIZE;
use atftp::server::{Config, Server};

#[derive(Parser, Debug)]
#[command(
    name = "atftpd",
    version,
    about = "TFTP server (Rust clone of atftpd)",
    disable_help_subcommand = true
)]
struct Args {
    /// Address:port to listen on.
    #[arg(long, default_value = "0.0.0.0:69")]
    listen: SocketAddr,

    /// Root directory served. Requests are resolved relative to this.
    #[arg(long, default_value = ".")]
    root: PathBuf,

    /// Allow WRQ to overwrite existing files.
    #[arg(long)]
    allow_overwrite: bool,

    /// Per-packet retransmit timeout, in seconds.
    #[arg(long, default_value_t = 5)]
    timeout: u8,

    /// Maximum number of retransmits before declaring a transfer dead.
    #[arg(long, default_value_t = 5)]
    retries: u32,

    /// Cap for the negotiated `blksize` option.
    #[arg(long, default_value_t = MAX_BLOCK_SIZE)]
    max_block_size: u16,

    /// Refuse the `windowsize` option (RFC 7440); fall back to lockstep.
    #[arg(long)]
    no_windowsize: bool,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace). Overridden by
    /// RUST_LOG if set.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing(args.verbose);

    let cfg = Config {
        listen: args.listen,
        root: args.root,
        allow_overwrite: args.allow_overwrite,
        timeout: Duration::from_secs(args.timeout as u64),
        retries: args.retries,
        max_block_size: args.max_block_size,
        allow_windowsize: !args.no_windowsize,
    };

    let server = Server::new(cfg);
    let serve = server.run();
    tokio::select! {
        r = serve => r.context("server exited with error")?,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c, shutting down");
        }
    }
    Ok(())
}
