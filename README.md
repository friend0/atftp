# aitftp

A Rust implementation of the Trivial File Transfer Protocol (TFTP) — a
clean-room rewrite of [madmartin/atftp][upstream], the C reference
client and server. It ships two binaries (`aitftp`, `aitftpd`) plus a
library that lets you embed either side in your own async Rust code.

The `ai-` prefix nods to its origin (a Claude-assisted port) and keeps
the binary names from colliding with upstream `atftp` / `atftpd` on the
same `$PATH`.

[upstream]: https://github.com/madmartin/atftp

## What is this a copy of?

[atftp][upstream] is the long-standing "advanced TFTP" project: a C
client/server pair widely used for PXE network boot, embedded firmware
provisioning, and any other scenario where TFTP's tiny footprint is the
right answer. This repository reimplements the same protocol surface in
Rust, with the same external behavior on the wire but a different
project structure inside.

| | upstream `atftp` | this repo |
| --- | --- | --- |
| Language | C (~50 source files) | Rust (~3,200 lines) |
| Async runtime | pthreads (thread-per-transfer) | tokio (task-per-transfer) |
| Build | autotools | cargo |
| Client REPL | libreadline, interactive | non-interactive CLI only |
| Multicast (RFC 2090) | yes | not implemented |
| MTFTP / PXE multicast | yes | not implemented |
| PCRE filename mapping | yes | not implemented |
| Library use | none (binary only) | first-class — see below |

No upstream source was copied; only the project's public README and
manual pages were consulted to confirm semantics.

## Protocol coverage

| RFC | What it adds | Supported |
| --- | --- | --- |
| 1350 | Base TFTP (RRQ/WRQ/DATA/ACK/ERROR, octet + netascii) | yes |
| 2347 | Option-extension framework + OACK | yes |
| 2348 | `blksize` option | yes |
| 2349 | `timeout` and `tsize` options | yes |
| 7440 | `windowsize` option | yes |
| 2090 | Multicast TFTP | no |

Out-of-window TIDs are answered with `ERROR(UnknownTid)` per RFC 1350
§4. Path traversal is rejected at the server (`../`, absolute paths,
embedded NULs all refused).

## Install

```
cargo build --release
```

That produces:

- `target/release/aitftp`  — the client
- `target/release/aitftpd` — the server

The crate is a single Cargo package with one library and two `[[bin]]`
targets; everything you need is in `Cargo.toml`.

## CLI usage

### Server

```
aitftpd --listen 0.0.0.0:69 --root /srv/tftp

# Common variations
aitftpd --listen 127.0.0.1:6969 --root ./files --allow-overwrite -v
aitftpd --listen 0.0.0.0:69 --root /srv/tftp --no-windowsize --max-block-size 1428
```

Flags:

| Flag | Default | Notes |
| --- | --- | --- |
| `--listen <addr:port>` | `0.0.0.0:69` | Privileged port; usually run as root or via setcap |
| `--root <dir>` | `.` | Resolved with `realpath` once at startup; requests are confined to it |
| `--allow-overwrite` | off | Without it, WRQ to an existing file returns `FileExists` |
| `--timeout <secs>` | `5` | Per-packet retransmit interval |
| `--retries <n>` | `5` | Retransmit budget before declaring a transfer dead |
| `--max-block-size <n>` | `65464` | Cap for the negotiated `blksize` |
| `--no-windowsize` | off | Refuse the `windowsize` option (falls back to lockstep) |
| `-v` / `-vv` / `-vvv` | off | warn → info → debug → trace (overridden by `RUST_LOG`) |

Stops cleanly on `SIGINT` (Ctrl-C); in-flight transfers finish on their
own sockets.

### Client

```
# Download
aitftp 192.168.1.1 get vmlinuz -l ./vmlinuz

# Upload
aitftp 192.168.1.1 put config.bin -l ./config.bin

# With negotiated options
aitftp 192.168.1.1 --blksize 1428 --windowsize 8 --tsize get image.img
```

Host accepts `host` or `host:port` (defaults to port 69). Subcommands
are `get` and `put`. Without `-l`, the local filename defaults to the
basename of the remote one.

## Library usage

The crate exposes a `Client` and a `Server` you can drop into your own
tokio application.

### Client

```rust
use aitftp::client::Client;
use aitftp::proto::Mode;
use std::time::Duration;

let addr = "192.168.1.1:69".parse().unwrap();

// Quick path: defaults
let client = Client::new(addr);
client.get("vmlinuz", "./vmlinuz".as_ref()).await?;

// Builder: customize per-transfer behavior
let client = Client::builder()
    .mode(Mode::Octet)
    .blksize(1428)
    .windowsize(8)
    .request_tsize(true)
    .timeout(Duration::from_secs(2))
    .retries(5)
    .build(addr);

// File I/O
let n: u64 = client.put("image.img", "./image.img".as_ref()).await?;

// In-memory I/O — never touch the disk
let bytes: Vec<u8> = client.get_to_vec("config.toml").await?;
client.put_bytes("payload.bin", &bytes).await?;
```

`Client` is `Clone + Send`; each method call binds its own ephemeral UDP
socket, so one client can drive many concurrent transfers.

### Server

```rust
use aitftp::server::Server;
use std::time::Duration;

let server = Server::builder()
    .listen("0.0.0.0:6969".parse().unwrap())
    .root("/srv/tftp")
    .allow_overwrite(false)
    .timeout(Duration::from_secs(5))
    .bind()                  // canonicalizes root, binds UDP socket
    .await?;

println!("listening on {}", server.local_addr());

// Block forever
server.run().await?;

// Or: stop cleanly when a future resolves
let shutdown = async { let _ = tokio::signal::ctrl_c().await; };
server.run_until(shutdown).await?;
```

`bind()` is async and returns `Result<Server>` so configuration errors
(missing root, port in use, etc.) surface before the accept loop starts.
`local_addr()` is the real bound address — useful when listening on
port 0 in tests.

## Testing

```
cargo test
```

The suite covers:

- 32 library unit tests (wire format, option negotiation, netascii
  translation, path-safety, client/server builder plumbing)
- 12 end-to-end tests on real UDP sockets (octet + netascii, file +
  in-memory, windowsize, error paths, graceful shutdown)

Interop with the macOS BSD `tftp` client has been verified in both
directions for sizes up to ~200 KB.

## What's not (yet) implemented

These are intentionally out of scope for the current release:

- RFC 2090 multicast TFTP
- MTFTP / PXE-style multicast extension
- PCRE-based filename rewriting on the server
- Interactive readline-style client REPL
- Privilege drop after binding port 69
- inetd-style stdin/stdout server mode

If you need any of them, open an issue.

## License

MIT — see [LICENSE](LICENSE).
