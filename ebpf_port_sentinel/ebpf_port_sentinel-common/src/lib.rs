#![no_std]

/// Number of leading payload bytes captured for each connection.
pub const PREFIX_LEN: usize = 20;

pub const FAMILY_IPV4: u8 = 4;
pub const FAMILY_IPV6: u8 = 6;

/// Identifies a TCP connection (as seen on the ingress path: client -> server).
/// Addresses are in network byte order; an IPv4 address uses the first 4 bytes.
/// No implicit padding: this struct is a BPF map key, so every byte must be defined.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnKey {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    /// FAMILY_IPV4 or FAMILY_IPV6.
    pub family: u8,
    pub _pad: [u8; 3],
}

/// Sent from the kernel to user space once per connection, carrying the
/// first bytes of the payload.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnEvent {
    pub key: ConnKey,
    /// Number of valid bytes in `prefix` (<= PREFIX_LEN).
    pub len: u16,
    pub _pad: u16,
    pub prefix: [u8; PREFIX_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnEvent {}
