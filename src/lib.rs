//! Rust clone of [atftp](https://github.com/madmartin/atftp) — a TFTP
//! client and server library plus matching binaries.
//!
//! Layered as:
//! * [`proto`] — pure wire format (RFC 1350 + 2347 + 2348 + 2349 + 7440).
//! * [`netascii`] — streaming netascii line-ending translator.
//! * [`path_safe`] — path resolver that refuses traversal.
//! * [`error`] — single error type used across the crate.
//! * [`server`] / [`client`] — async I/O state machines built on tokio.

pub mod client;
pub mod error;
pub mod netascii;
pub mod path_safe;
pub mod proto;
pub mod server;

pub use error::{Error, Result};
