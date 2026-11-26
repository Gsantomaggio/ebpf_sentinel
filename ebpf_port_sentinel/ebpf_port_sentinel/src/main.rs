use anyhow::Context as _;

mod jev;
mod validator;

use std::path::PathBuf;

use validator::{Connection, LogValidator};

use aya::maps::{HashMap, RingBuf};
use aya::programs::{Xdp, XdpMode};
use clap::Parser;
use ebpf_port_sentinel_common::ConnEvent;
use log::{debug, info, warn};
use tokio::io::{Interest, unix::AsyncFd};
use tokio::{signal, sync::mpsc};

#[derive(Debug, Parser)]
struct Opt {
    /// Interface(s) to attach to; repeat the flag or use a comma-separated list.
    #[clap(short, long, default_value = "eth0", value_delimiter = ',')]
    iface: Vec<String>,
    /// TCP destination port(s) to watch; repeat the flag or use a comma-separated list.
    #[clap(short, long, required = true, value_delimiter = ',')]
    port: Vec<u16>,
    /// Send the first bytes of every connection to the Jev model to validate the protocol.
    /// Disabled by default; the bytes leave this machine when enabled.
    #[clap(long = "enable_jev", alias = "enable-jev")]
    enable_jev: bool,
    /// File holding the TypeSafe API key (bare key or `NAME=key`). `TYPESAFE_API_KEY` wins.
    #[clap(long, default_value = "env")]
    jev_key_file: PathBuf,
    /// Jev model name or alias.
    #[clap(long, default_value = "jev-latest")]
    jev_model: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf_port_sentinel"
    )))?;
    let Opt { iface, port: ports, enable_jev, jev_key_file, jev_model } = opt;

    // Fail before attaching anything if Jev is requested but cannot be set up.
    let jev = if enable_jev {
        let key = jev::load_api_key(&jev_key_file)?;
        Some(jev::JevValidator::new(key, jev_model.clone())?)
    } else {
        None
    };

    let mut watched: HashMap<_, u16, u8> =
        HashMap::try_from(ebpf.map_mut("PORTS").context("no PORTS map")?)?;
    for port in &ports {
        watched.insert(port, 1, 0)?;
    }

    let events = RingBuf::try_from(ebpf.take_map("EVENTS").context("no EVENTS map")?)?;
    // SAFETY: the RingBuf owns its fd and AsyncFd takes ownership of the RingBuf.
    let mut events = unsafe { AsyncFd::register_with_interest(events, Interest::READABLE) }?;

    let program: &mut Xdp = ebpf.program_mut("ebpf_port_sentinel").unwrap().try_into()?;
    program.load()?;
    for name in &iface {
        program.attach(name, XdpMode::default()).with_context(|| {
            format!("failed to attach the XDP program to {name} (try XdpMode::SkbMode)")
        })?;
    }

    info!(
        "watching TCP port(s) {ports:?} on {}, Ctrl-C to exit (jev {})",
        iface.join(","),
        if enable_jev { format!("enabled, model {jev_model}") } else { "disabled".into() }
    );

    // Capture -> validator hand-off. A slow validator (e.g. an LLM call) must not stall the
    // ring buffer reader, so events go through a bounded channel and are dropped when full.
    let (tx, rx) = mpsc::channel::<Connection>(1024);
    let validator_task = match jev {
        Some(jev) => tokio::spawn(validator::run(jev, rx)),
        None => tokio::spawn(validator::run(LogValidator, rx)),
    };

    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            guard = events.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    if item.len() < size_of::<ConnEvent>() {
                        warn!("short event: {} bytes", item.len());
                        continue;
                    }
                    // SAFETY: ConnEvent is repr(C) plain data; length checked above.
                    let ev: ConnEvent = unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) };
                    if tx.try_send(Connection::from(&ev)).is_err() {
                        warn!("validator is behind, dropping connection event");
                    }
                }
                guard.clear_ready();
            }
        }
    }
    drop(tx);
    let _ = validator_task.await;
    info!("exiting");

    Ok(())
}
