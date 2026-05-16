//! End-to-end tests: real UDP, real ephemeral ports, server task and
//! client task in the same process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use atftp::client::{Client, Options};
use atftp::error::Error;
use atftp::proto::Mode;
use atftp::server::{Config, Server};
use tokio::time::timeout;

/// Spawn a server on an ephemeral port and return its bound addr plus
/// a handle the test can use to keep the task alive (drop = abort).
async fn spawn_server(root: PathBuf, mut cfg: Config) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    cfg.root = root;
    let server = Server::bind(cfg).await.unwrap();
    let addr = server.local_addr();
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    (addr, handle)
}

fn base_cfg() -> Config {
    Config {
        timeout: Duration::from_millis(500),
        retries: 3,
        ..Config::default()
    }
}

fn base_opts() -> Options {
    Options {
        timeout: Duration::from_millis(500),
        retries: 3,
        ..Options::default()
    }
}

fn client_with(addr: SocketAddr, opts: Options) -> Client {
    Client::with_options(addr, opts)
}

async fn write_file(path: &std::path::Path, data: &[u8]) {
    tokio::fs::write(path, data).await.unwrap();
}

async fn read_file(path: &std::path::Path) -> Vec<u8> {
    tokio::fs::read(path).await.unwrap()
}

#[tokio::test]
async fn rrq_octet_small_no_options() {
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    let client_dir = dir.path().join("cli");
    tokio::fs::create_dir(&server_root).await.unwrap();
    tokio::fs::create_dir(&client_dir).await.unwrap();
    let payload = b"hello tftp\n";
    write_file(&server_root.join("hi.txt"), payload).await;

    let (addr, _server) = spawn_server(server_root.clone(), base_cfg()).await;
    let dest = client_dir.join("hi.txt");
    let client = client_with(addr, base_opts());
    let n = timeout(Duration::from_secs(5), client.get("hi.txt", &dest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n as usize, payload.len());
    assert_eq!(read_file(&dest).await, payload);
}

#[tokio::test]
async fn rrq_octet_exact_block_boundary() {
    // Default blksize is 512 — exercise the empty-final-block branch.
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    let client_dir = dir.path().join("cli");
    tokio::fs::create_dir(&server_root).await.unwrap();
    tokio::fs::create_dir(&client_dir).await.unwrap();
    let payload = vec![b'A'; 512];
    write_file(&server_root.join("blk.bin"), &payload).await;

    let (addr, _server) = spawn_server(server_root.clone(), base_cfg()).await;
    let dest = client_dir.join("blk.bin");
    let client = client_with(addr, base_opts());
    let n = timeout(Duration::from_secs(5), client.get("blk.bin", &dest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n as usize, payload.len());
    assert_eq!(read_file(&dest).await, payload);
}

#[tokio::test]
async fn rrq_octet_large_with_options() {
    // ~1.2 MB at default blksize would be slow (2400 round trips). With
    // blksize=1428 + windowsize=8 it's a few hundred packets.
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    let client_dir = dir.path().join("cli");
    tokio::fs::create_dir(&server_root).await.unwrap();
    tokio::fs::create_dir(&client_dir).await.unwrap();
    let mut payload = Vec::with_capacity(1_200_003);
    for i in 0..payload.capacity() {
        payload.push((i & 0xff) as u8);
    }
    write_file(&server_root.join("big.bin"), &payload).await;

    let (addr, _server) = spawn_server(server_root.clone(), base_cfg()).await;
    let dest = client_dir.join("big.bin");
    let client = Client::builder()
        .blksize(1428)
        .windowsize(8)
        .request_tsize(true)
        .timeout(Duration::from_millis(500))
        .retries(3)
        .build(addr);
    let n = timeout(Duration::from_secs(15), client.get("big.bin", &dest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n as usize, payload.len());
    assert_eq!(read_file(&dest).await, payload);
}

#[tokio::test]
async fn rrq_file_not_found_surfaces_peer_error() {
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    tokio::fs::create_dir(&server_root).await.unwrap();
    let (addr, _server) = spawn_server(server_root, base_cfg()).await;

    let dest = dir.path().join("won't-exist");
    let client = client_with(addr, base_opts());
    let err = timeout(Duration::from_secs(5), client.get("missing.bin", &dest))
        .await
        .unwrap()
        .unwrap_err();
    match err {
        Error::Peer { code, .. } => {
            assert_eq!(code, atftp::proto::ErrorCode::FileNotFound);
        }
        other => panic!("expected Peer error, got {other:?}"),
    }
}

#[tokio::test]
async fn rrq_path_traversal_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    tokio::fs::create_dir(&server_root).await.unwrap();
    // Put a sensitive file *outside* the root.
    write_file(&dir.path().join("secret.txt"), b"shhh").await;
    let (addr, _server) = spawn_server(server_root, base_cfg()).await;

    let dest = dir.path().join("stolen.txt");
    let client = client_with(addr, base_opts());
    let err = timeout(Duration::from_secs(5), client.get("../secret.txt", &dest))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Peer {
            code: atftp::proto::ErrorCode::AccessViolation,
            ..
        }
    ));
}

#[tokio::test]
async fn wrq_octet_small() {
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    let client_dir = dir.path().join("cli");
    tokio::fs::create_dir(&server_root).await.unwrap();
    tokio::fs::create_dir(&client_dir).await.unwrap();
    let src = client_dir.join("up.bin");
    let payload = b"upload payload data\n";
    write_file(&src, payload).await;

    let (addr, _server) = spawn_server(server_root.clone(), base_cfg()).await;
    let client = client_with(addr, base_opts());
    let n = timeout(Duration::from_secs(5), client.put("up.bin", &src))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n as usize, payload.len());
    let landed = read_file(&server_root.join("up.bin")).await;
    assert_eq!(landed, payload);
}

#[tokio::test]
async fn wrq_refuses_overwrite_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    let client_dir = dir.path().join("cli");
    tokio::fs::create_dir(&server_root).await.unwrap();
    tokio::fs::create_dir(&client_dir).await.unwrap();
    write_file(&server_root.join("exists.bin"), b"original").await;
    let src = client_dir.join("exists.bin");
    write_file(&src, b"replacement").await;

    let (addr, _server) = spawn_server(server_root.clone(), base_cfg()).await;
    let client = client_with(addr, base_opts());
    let err = timeout(Duration::from_secs(5), client.put("exists.bin", &src))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Peer {
            code: atftp::proto::ErrorCode::FileExists,
            ..
        }
    ));
    // And the original file is untouched.
    let on_disk = read_file(&server_root.join("exists.bin")).await;
    assert_eq!(on_disk, b"original");
}

#[tokio::test]
async fn wrq_overwrite_when_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    let client_dir = dir.path().join("cli");
    tokio::fs::create_dir(&server_root).await.unwrap();
    tokio::fs::create_dir(&client_dir).await.unwrap();
    write_file(&server_root.join("exists.bin"), b"original-and-longer").await;
    let src = client_dir.join("exists.bin");
    let payload = b"replacement";
    write_file(&src, payload).await;

    let cfg = Config {
        allow_overwrite: true,
        ..base_cfg()
    };
    let (addr, _server) = spawn_server(server_root.clone(), cfg).await;
    let client = client_with(addr, base_opts());
    timeout(Duration::from_secs(5), client.put("exists.bin", &src))
        .await
        .unwrap()
        .unwrap();
    let on_disk = read_file(&server_root.join("exists.bin")).await;
    assert_eq!(on_disk, payload);
}

#[tokio::test]
async fn netascii_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    let client_dir = dir.path().join("cli");
    tokio::fs::create_dir(&server_root).await.unwrap();
    tokio::fs::create_dir(&client_dir).await.unwrap();
    // Multi-line text with a few embedded CRs to exercise both
    // translation directions.
    let text = b"line one\nline two\nline three with a CR\rin the middle\n";
    write_file(&client_dir.join("notes.txt"), text).await;

    let (addr, _server) = spawn_server(server_root.clone(), base_cfg()).await;

    let opts = Options {
        mode: Mode::NetAscii,
        ..base_opts()
    };
    let client = client_with(addr, opts);

    timeout(
        Duration::from_secs(5),
        client.put("notes.txt", &client_dir.join("notes.txt")),
    )
    .await
    .unwrap()
    .unwrap();

    let dest = client_dir.join("notes-roundtrip.txt");
    timeout(Duration::from_secs(5), client.get("notes.txt", &dest))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(read_file(&dest).await, text);
}

#[tokio::test]
async fn rrq_with_windowsize_only() {
    // Negotiate windowsize but keep default blksize, hitting the
    // multi-block-per-ACK code path on small files.
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    let client_dir = dir.path().join("cli");
    tokio::fs::create_dir(&server_root).await.unwrap();
    tokio::fs::create_dir(&client_dir).await.unwrap();
    // 5 default-blocks = 2560 bytes; with windowsize=4 we send 4 then 1.
    let payload = vec![b'Z'; 2560];
    write_file(&server_root.join("w.bin"), &payload).await;
    let (addr, _server) = spawn_server(server_root.clone(), base_cfg()).await;
    let dest = client_dir.join("w.bin");
    let opts = Options {
        windowsize: Some(4),
        ..base_opts()
    };
    let client = client_with(addr, opts);
    timeout(Duration::from_secs(5), client.get("w.bin", &dest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read_file(&dest).await, payload);
}

#[tokio::test]
async fn graceful_shutdown_via_run_until() {
    // run_until should return promptly once the shutdown future resolves.
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    tokio::fs::create_dir(&server_root).await.unwrap();
    let mut cfg = base_cfg();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    cfg.root = server_root;
    let server = Server::bind(cfg).await.unwrap();
    let addr = server.local_addr();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        server
            .run_until(async {
                let _ = rx.await;
            })
            .await
    });

    // Sanity-check the server actually listens: a quick get on a
    // nonexistent file should round-trip as FileNotFound, proving the
    // listener is alive before we signal shutdown.
    let client = client_with(addr, base_opts());
    let dest = dir.path().join("nope");
    let err = timeout(Duration::from_secs(2), client.get("nope.bin", &dest))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, Error::Peer { .. }));

    // Signal shutdown and confirm the task exits cleanly.
    tx.send(()).unwrap();
    let result = timeout(Duration::from_secs(2), join)
        .await
        .expect("server didn't shut down in time")
        .expect("join failed");
    result.expect("run_until returned an error");
}

#[tokio::test]
async fn bytes_round_trip_in_memory() {
    // Library-user flavor: put_bytes / get_to_vec without touching disk.
    let dir = tempfile::tempdir().unwrap();
    let server_root = dir.path().join("srv");
    tokio::fs::create_dir(&server_root).await.unwrap();
    let cfg = Config {
        allow_overwrite: true,
        ..base_cfg()
    };
    let (addr, _server) = spawn_server(server_root.clone(), cfg).await;

    let payload: Vec<u8> = (0..5000u32).map(|i| (i & 0xff) as u8).collect();
    let client = Client::builder()
        .blksize(1024)
        .windowsize(4)
        .request_tsize(true)
        .timeout(Duration::from_millis(500))
        .retries(3)
        .build(addr);

    let sent = timeout(
        Duration::from_secs(5),
        client.put_bytes("mem.bin", &payload),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(sent as usize, payload.len());

    let got = timeout(Duration::from_secs(5), client.get_to_vec("mem.bin"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, payload);
}
