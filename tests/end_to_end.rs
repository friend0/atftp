//! End-to-end tests: real UDP, real ephemeral ports, server task and
//! client task in the same process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use atftp::client::{self, Options};
use atftp::error::Error;
use atftp::proto::Mode;
use atftp::server::{Config, Server};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Spawn a server on an ephemeral port and return its bound addr plus
/// a handle the test can use to keep the task alive (drop = abort).
async fn spawn_server(root: PathBuf, mut cfg: Config) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // Bind a probe socket to claim a port, then immediately drop it so
    // the server can re-bind. There's a tiny race window but it has
    // never bitten in practice for these short-lived tests.
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    cfg.listen = addr;
    cfg.root = root;
    let server = Server::new(cfg);
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    // Give the server a moment to actually bind before clients try.
    tokio::time::sleep(Duration::from_millis(50)).await;
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
    let n = timeout(
        Duration::from_secs(5),
        client::get(addr, "hi.txt", &dest, &base_opts()),
    )
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
    let n = timeout(
        Duration::from_secs(5),
        client::get(addr, "blk.bin", &dest, &base_opts()),
    )
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
    let opts = Options {
        blksize: Some(1428),
        windowsize: Some(8),
        request_tsize: true,
        ..base_opts()
    };
    let n = timeout(
        Duration::from_secs(15),
        client::get(addr, "big.bin", &dest, &opts),
    )
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
    let err = timeout(
        Duration::from_secs(5),
        client::get(addr, "missing.bin", &dest, &base_opts()),
    )
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
    let err = timeout(
        Duration::from_secs(5),
        client::get(addr, "../secret.txt", &dest, &base_opts()),
    )
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
    let opts = base_opts();
    let n = timeout(
        Duration::from_secs(5),
        client::put(addr, "up.bin", &src, &opts),
    )
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
    let err = timeout(
        Duration::from_secs(5),
        client::put(addr, "exists.bin", &src, &base_opts()),
    )
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
    timeout(
        Duration::from_secs(5),
        client::put(addr, "exists.bin", &src, &base_opts()),
    )
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

    timeout(
        Duration::from_secs(5),
        client::put(addr, "notes.txt", &client_dir.join("notes.txt"), &opts),
    )
    .await
    .unwrap()
    .unwrap();

    let dest = client_dir.join("notes-roundtrip.txt");
    timeout(
        Duration::from_secs(5),
        client::get(addr, "notes.txt", &dest, &opts),
    )
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
    timeout(
        Duration::from_secs(5),
        client::get(addr, "w.bin", &dest, &opts),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read_file(&dest).await, payload);
}
