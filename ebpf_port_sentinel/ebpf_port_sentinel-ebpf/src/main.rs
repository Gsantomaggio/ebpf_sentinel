#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_NOEXIST, xdp_action},
    helpers::bpf_xdp_load_bytes,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap, RingBuf},
    programs::XdpContext,
};
use ebpf_port_sentinel_common::{ConnEvent, ConnKey, FAMILY_IPV4, FAMILY_IPV6, PREFIX_LEN};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPV6_HDR_LEN: usize = 40;
const IPPROTO_TCP: u8 = 6;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

/// TCP destination ports to watch (keys; set by user space before attaching).
#[map]
static PORTS: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

/// Connections whose first bytes were already reported. LRU so that
/// connections that vanish without FIN/RST are eventually evicted.
#[map]
static SEEN: LruHashMap<ConnKey, u8> = LruHashMap::with_max_entries(65536, 0);

/// Events towards user space.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[xdp]
pub fn ebpf_port_sentinel(ctx: XdpContext) -> u32 {
    try_sentinel(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + core::mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn read_u8(ctx: &XdpContext, offset: usize) -> Result<u8, ()> {
    Ok(unsafe { *ptr_at::<u8>(ctx, offset)? })
}

#[inline(always)]
fn read_be16(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    Ok(u16::from_be_bytes([
        read_u8(ctx, offset)?,
        read_u8(ctx, offset + 1)?,
    ]))
}

#[inline(always)]
fn read_be32(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    Ok(u32::from_be_bytes([
        read_u8(ctx, offset)?,
        read_u8(ctx, offset + 1)?,
        read_u8(ctx, offset + 2)?,
        read_u8(ctx, offset + 3)?,
    ]))
}

/// The monitor never drops traffic: every error path ends in XDP_PASS.
///
/// Every packet that arrives on the interface goes through here, so most of this function is
/// about *leaving early*: a packet is narrowed down in stages, and only the one that opens a
/// watched connection reaches the ring buffer.
///
///   1. not IPv4/IPv6 (ARP, VLAN-tagged, ...)         -> pass   (other traffic)
///   2. not TCP (UDP, ICMP, ...), IP fragment         -> pass   (other traffic)
///   3. TCP, but destination port not in `PORTS`      -> pass   (other TCP traffic)
///   4. watched port, but FIN/RST                     -> forget the connection, pass
///   5. watched port, but no payload (SYN, pure ACK)  -> pass   (handshake, not yet "data")
///   6. watched port, first packet WITH payload       -> **the connection is detected here**:
///      `SEEN.insert(.., BPF_NOEXIST)` succeeds only once per connection key, so the first
///      payload packet is reported and every later packet of the same connection is passed.
///
/// A connection is therefore "detected" at its first data segment (for AMQP, the protocol header
/// sent right after the TCP handshake), not at the SYN, because the protocol is only visible in
/// the payload.
fn try_sentinel(ctx: &XdpContext) -> Result<u32, ()> {
    let pass = Ok(xdp_action::XDP_PASS);

    let mut key = ConnKey {
        src_addr: [0; 16],
        dst_addr: [0; 16],
        src_port: 0,
        dst_port: 0,
        family: 0,
        _pad: [0; 3],
    };
    // Offset of the TCP header and number of bytes in the TCP segment (header + payload).
    let tcp: usize;
    let l4_len: usize;

    // Stages 1-2: separate IP/TCP from every other kind of traffic.
    // Ethernet (no VLAN) -> IPv4 or IPv6 -> TCP only.
    let ethertype = read_be16(ctx, 12)?;
    if ethertype == ETH_P_IP {
        let ip = ETH_HDR_LEN;
        let ihl = ((read_u8(ctx, ip)? & 0x0f) as usize) * 4;
        if ihl < 20 || read_u8(ctx, ip + 9)? != IPPROTO_TCP {
            return pass;
        }
        // Skip non-first fragments: they carry no TCP header.
        if read_be16(ctx, ip + 6)? & 0x1fff != 0 {
            return pass;
        }
        let ip_total_len = read_be16(ctx, ip + 2)? as usize;
        if ip_total_len < ihl {
            return pass;
        }
        key.family = FAMILY_IPV4;
        key.src_addr[..4].copy_from_slice(unsafe { &*ptr_at::<[u8; 4]>(ctx, ip + 12)? });
        key.dst_addr[..4].copy_from_slice(unsafe { &*ptr_at::<[u8; 4]>(ctx, ip + 16)? });
        tcp = ip + ihl;
        l4_len = ip_total_len - ihl;
    } else if ethertype == ETH_P_IPV6 {
        let ip = ETH_HDR_LEN;
        // Only TCP directly after the fixed header (extension headers are not followed).
        if read_u8(ctx, ip + 6)? != IPPROTO_TCP {
            return pass;
        }
        key.family = FAMILY_IPV6;
        key.src_addr = unsafe { *ptr_at::<[u8; 16]>(ctx, ip + 8)? };
        key.dst_addr = unsafe { *ptr_at::<[u8; 16]>(ctx, ip + 24)? };
        tcp = ip + IPV6_HDR_LEN;
        l4_len = read_be16(ctx, ip + 4)? as usize; // payload length, excludes the fixed header
    } else {
        return pass;
    }

    // Check the whole fixed TCP header once; every field is then read at a
    // constant offset from this single verified pointer.
    let th = ptr_at::<[u8; 20]>(ctx, tcp)?;
    let th = unsafe { &*th };
    let dst_port = u16::from_be_bytes([th[2], th[3]]);
    // Stage 3: the line between "any TCP" and "TCP we care about". Only packets travelling
    // towards a watched port (client -> server) continue; replies from the server have the
    // watched port as *source* and stop here, as does all TCP traffic to other ports.
    if unsafe { PORTS.get(&dst_port) }.is_none() {
        return pass;
    }

    key.src_port = u16::from_be_bytes([th[0], th[1]]);
    key.dst_port = dst_port;

    // Stage 4: the connection is closing; drop its SEEN entry so that a later connection reusing
    // the same source port is detected again.
    if th[13] & (TCP_FIN | TCP_RST) != 0 {
        let _ = SEEN.remove(&key);
        return pass;
    }

    let tcp_hdr_len = ((th[12] >> 4) as usize) * 4;
    if tcp_hdr_len < 20 || l4_len < tcp_hdr_len {
        return pass;
    }
    let payload_len = l4_len - tcp_hdr_len;
    // Stage 5: SYN, SYN-ACK and pure ACKs carry no payload, so there is nothing to inspect yet.
    if payload_len == 0 {
        return pass; // handshake / pure ACK
    }

    // Stage 6: THIS is where a new connection is detected. The packet is on a watched port, is
    // not a FIN/RST and carries data. Atomically claim the connection key: the insert succeeds
    // for the first such packet only (BPF_NOEXIST); for every later packet of the same
    // connection it fails and we return without reporting again.
    if SEEN.insert(&key, &1, BPF_NOEXIST as u64).is_err() { // <-- stage 6: detection point
        return pass;
    }

    // Copy up to PREFIX_LEN payload bytes with the kernel helper (Linux >= 5.18);
    // it handles bounds itself, so no per-byte verifier-visible checks are needed.
    let mut prefix = [0u8; PREFIX_LEN];
    // black_box keeps LLVM from folding away the range check the verifier needs.
    let len = core::hint::black_box(payload_len.min(PREFIX_LEN));
    if len == 0 || len > PREFIX_LEN {
        let _ = SEEN.remove(&key);
        return pass;
    }
    let ret = unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            (tcp + tcp_hdr_len) as u32,
            prefix.as_mut_ptr() as *mut core::ffi::c_void,
            len as u32,
        )
    };
    if ret != 0 {
        let _ = SEEN.remove(&key);
        return pass;
    }

    if let Some(mut entry) = EVENTS.reserve::<ConnEvent>(0) {
        entry.write(ConnEvent {
            key,
            len: len as u16,
            _pad: 0,
            prefix,
        });
        entry.submit(0);
    }
    pass
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
