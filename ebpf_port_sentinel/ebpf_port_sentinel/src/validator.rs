//! Hand-off point between the kernel capture and whatever judges the connection.
//!
//! The capture side is protocol-agnostic: it forwards the first bytes of *every* new TCP
//! connection to the watched port. A `Validator` decides what to do with them.
//! `LogValidator` just logs; `crate::jev::JevValidator` asks the Jev model which protocol the
//! bytes belong to.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use ebpf_port_sentinel_common::{ConnEvent, FAMILY_IPV6};
use log::info;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

/// How many connections may be validated at the same time.
const MAX_IN_FLIGHT: usize = 8;

pub fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Printable ASCII as is, everything else as `.`.
pub fn ascii_of(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}

/// A new connection and the first bytes it sent, in a form that is easy to hand to a validator.
#[derive(Debug, Clone)]
pub struct Connection {
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
    /// Up to 20 bytes: the start of the connection's payload.
    pub first_bytes: Vec<u8>,
}

fn ip_from(family: u8, addr: [u8; 16]) -> IpAddr {
    if family == FAMILY_IPV6 {
        IpAddr::V6(Ipv6Addr::from(addr))
    } else {
        IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
    }
}

impl From<&ConnEvent> for Connection {
    fn from(ev: &ConnEvent) -> Self {
        let n = (ev.len as usize).min(ev.prefix.len());
        Self {
            src: (ip_from(ev.key.family, ev.key.src_addr), ev.key.src_port),
            dst: (ip_from(ev.key.family, ev.key.dst_addr), ev.key.dst_port),
            first_bytes: ev.prefix[..n].to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing to say (or the connection looks fine).
    Ok,
    /// The validator flagged the connection, with a reason.
    Suspicious(String),
}

pub trait Validator {
    /// `Err` means the validator could not judge (e.g. the API was unreachable). It is not a
    /// verdict: callers must not read it as "fine" or as "suspicious".
    fn validate<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = anyhow::Result<Verdict>> + Send + 'a;
}

/// Placeholder validator: just logs what it was given.
pub struct LogValidator;

impl Validator for LogValidator {
    async fn validate(&self, conn: &Connection) -> anyhow::Result<Verdict> {
        info!(
            "new connection {} -> {} first {} bytes: [{}] \"{}\"",
            SocketAddr::new(conn.src.0, conn.src.1),
            SocketAddr::new(conn.dst.0, conn.dst.1),
            conn.first_bytes.len(),
            hex_of(&conn.first_bytes),
            ascii_of(&conn.first_bytes)
        );
        Ok(Verdict::Ok)
    }
}

/// Consume connections from `rx` until the sender side is dropped, validating up to
/// `MAX_IN_FLIGHT` at a time. Returns once every started validation has finished.
pub async fn run<V: Validator + Send + Sync + 'static>(validator: V, mut rx: mpsc::Receiver<Connection>) {
    let validator = Arc::new(validator);
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks = JoinSet::new();
    while let Some(conn) = rx.recv().await {
        // Waiting here lets the channel fill up, which makes the capture side drop events
        // instead of piling up unbounded work.
        let Ok(permit) = permits.clone().acquire_owned().await else { break };
        let validator = validator.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let (src, dst) = (SocketAddr::new(conn.src.0, conn.src.1), SocketAddr::new(conn.dst.0, conn.dst.1));
            match validator.validate(&conn).await {
                Ok(Verdict::Ok) => {}
                Ok(Verdict::Suspicious(reason)) => {
                    log::warn!("suspicious connection {src} -> {dst}: {reason}")
                }
                Err(e) => log::error!("could not validate connection {src} -> {dst}: {e:#}"),
            }
        });
        // Reap finished tasks so the set does not grow forever.
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
}
