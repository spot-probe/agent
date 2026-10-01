//! ICMP echo: the packet half.
//!
//! Building and reading a packet is pure and tested below; carrying it over a
//! socket is `ping_once`, which is only reached where the process is allowed to
//! open one. That is why its errors are told apart rather than collapsed into a
//! timeout: **a probe that cannot run must not look like a probe that timed out.**
//!
//! IPv4 first. ICMPv6 (types 128/129, whose checksum covers a pseudo-header) is the
//! next step; the shapes here are what it will follow.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

/// ICMPv6 is a later step; the v4 types are what this file speaks today.
pub const ECHO_REQUEST: u8 = 8;
pub const ECHO_REPLY: u8 = 0;

/// One's complement of the one's complement sum of 16-bit big-endian words, with a
/// trailing odd byte padded on the right -- the checksum both IP and ICMP use.
///
/// Property the tests lean on: a message whose checksum field is already correct
/// sums to zero.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        sum += u32::from(bytes[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An echo request with its checksum filled in.
///
/// The payload is a fixed eight bytes rather than nothing: an empty request is
/// answered by some middleboxes with an empty reply, and a payload makes a
/// truncated or unrelated reply easier to notice. Sixteen bytes in total is also a
/// length every path carries without fragmenting.
pub fn build_echo(id: u16, seq: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(16);
    packet.push(ECHO_REQUEST);
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum, filled in below
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(b"monitor!"); // eight bytes: header plus this is sixteen
    let sum = checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// The id and sequence of an echo **reply**, or `None` for anything else: a
/// different type, a code that is not zero, a packet too short to hold a header, or
/// a request that came back.
///
/// A reply from a **raw** socket arrives with the IPv4 header in front of it and one
/// from a **datagram** socket without, so both are accepted: the header is skipped
/// when the first byte says version 4, whose length is in its low nibble. Getting
/// this wrong is the difference between "no replies" and "wrong replies", and the
/// tests below pin both shapes.
pub fn parse_reply(buf: &[u8]) -> Option<(u16, u16)> {
    let message = match buf.first() {
        Some(first) if first >> 4 == 4 => {
            let header = usize::from(first & 0x0f) * 4;
            buf.get(header..)?
        }
        _ => buf,
    };
    if message.len() < 8 || message[0] != ECHO_REPLY || message[1] != 0 {
        return None;
    }
    Some((u16::from_be_bytes([message[4], message[5]]), u16::from_be_bytes([message[6], message[7]])))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The self-checking property: a message that carries its own correct checksum
    /// sums to zero.
    #[test]
    fn a_packet_with_its_checksum_filled_in_sums_to_zero() {
        let echo = build_echo(0x1234, 7);
        assert_eq!(checksum(&echo), 0, "the checksum it wrote must verify");
    }

    #[test]
    fn an_echo_request_says_what_it_is_and_carries_its_id_and_sequence() {
        let echo = build_echo(0xbeef, 0x0102);
        assert_eq!(echo[0], ECHO_REQUEST, "type 8");
        assert_eq!(echo[1], 0, "code 0");
        assert_eq!(&echo[4..6], &[0xbe, 0xef], "identifier");
        assert_eq!(&echo[6..8], &[0x01, 0x02], "sequence");
        assert_eq!(echo.len(), 16, "eight of header and eight of payload");
        // A different sequence must produce a different checksum, or the field is
        // not being computed from the message.
        assert_ne!(echo[2..4], build_echo(0xbeef, 0x0103)[2..4]);
    }

    #[test]
    fn a_datagram_sockets_reply_has_no_ip_header_to_skip() {
        let reply = [ECHO_REPLY, 0, 0x11, 0x22, 0xbe, 0xef, 0x01, 0x02];
        assert_eq!(parse_reply(&reply), Some((0xbeef, 0x0102)));
    }

    #[test]
    fn a_raw_sockets_reply_arrives_behind_its_ip_header() {
        // Version 4, IHL 5: twenty bytes of header, then the ICMP message.
        let mut packet = vec![0x45u8; 20];
        packet[0] = 0x45;
        packet.extend_from_slice(&[ECHO_REPLY, 0, 0x11, 0x22, 0xbe, 0xef, 0x01, 0x03]);
        assert_eq!(parse_reply(&packet), Some((0xbeef, 0x0103)), "the header is skipped by its IHL");
    }

    #[test]
    fn anything_that_is_not_a_reply_is_not_read_as_one() {
        // A request echoed back (some hosts answer a request with a request).
        assert_eq!(parse_reply(&build_echo(1, 1)), None, "type 8 is not a reply");
        // A reply with a non-zero code.
        assert_eq!(parse_reply(&[ECHO_REPLY, 0x03, 0, 0, 0, 1, 0, 1]), None, "code must be zero");
        // Too short to hold the fields it reads.
        assert_eq!(parse_reply(&[ECHO_REPLY, 0, 0, 0, 0, 1, 0]), None, "seven bytes is short");
        assert_eq!(parse_reply(&[]), None, "and nothing at all is not a reply");
        // An IPv4 header whose IHL runs past the buffer.
        assert_eq!(parse_reply(&[0x4f, 0, 0, 0, 0, 1, 0, 1]), None, "IHL 15 needs 60 bytes");
    }
}

/// Why a probe produced no sample.
///
/// Kept apart rather than collapsed into "no answer": **a probe that cannot run must
/// not look like a probe that timed out**, or the chart shows a probe at 100% loss
/// and every reader blames the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpError {
    /// Neither socket could be opened: needs `CAP_NET_RAW`, or a
    /// `net.ipv4.ping_group_range` covering this user's group.
    Permission,
    /// Sent, and nothing came back in time.
    Timeout,
    /// The socket failed for another reason.
    Socket,
    /// Not an address this probe can use -- IPv6 today.
    Address,
}

impl std::fmt::Display for IcmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Permission => "ICMP needs CAP_NET_RAW or a net.ipv4.ping_group_range                                  covering this agent's user",
            Self::Timeout => "no echo reply within the timeout",
            Self::Socket => "the ICMP socket failed",
            Self::Address => "this probe speaks IPv4 only for now",
        };
        f.write_str(text)
    }
}

/// One echo, one reply, one round trip.
///
/// Blocking on purpose: the agent's runtime is single-threaded and its cadence is
/// seconds, so the caller wraps this in `spawn_blocking` rather than the probe
/// growing an async socket layer of its own.
///
/// A **datagram** socket first, because the agent runs as the unprivileged
/// `monitor-agent` user and most hosts allow it; a **raw** socket as the fallback for
/// the hosts that do not. If both are refused the answer is `Permission`, never a
/// timeout -- see `IcmpError`.
///
/// The reply is matched on its **sequence**, not its identifier: an unprivileged
/// datagram socket has the kernel rewrite the id (it is the socket's port), so the
/// id we wrote never comes back on that path. Nothing else is listening on this
/// socket, so the sequence is what identifies it.
pub fn ping_once(addr: SocketAddr, timeout: Duration) -> Result<Duration, IcmpError> {
    if addr.is_ipv6() {
        return Err(IcmpError::Address);
    }
    let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
        Ok(socket) => socket,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
                Ok(socket) => socket,
                Err(e) if e.kind() == ErrorKind::PermissionDenied => return Err(IcmpError::Permission),
                Err(_) => return Err(IcmpError::Socket),
            }
        }
        Err(_) => return Err(IcmpError::Socket),
    };
    socket.set_read_timeout(Some(timeout)).map_err(|_| IcmpError::Socket)?;

    // Changing every round, so a reply that arrives late for the previous one is not
    // read as this one's.
    let seq = (Instant::now().elapsed().subsec_nanos() % u32::from(u16::MAX)) as u16;
    let packet = build_echo(std::process::id() as u16, seq);
    let started = Instant::now();
    socket.send_to(&packet, &addr.into()).map_err(|e| match e.kind() {
        ErrorKind::PermissionDenied => IcmpError::Permission,
        _ => IcmpError::Socket,
    })?;

    // `socket2` 0.6 takes `&mut [MaybeUninit<u8>]` here. The kernel writes `n` bytes and
    // reports `n`, so reading exactly those as `u8` is sound; this is the only
    // `unsafe` in the file.
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                let filled = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                if parse_reply(filled).is_some_and(|(_, got)| got == seq) {
                    return Ok(started.elapsed());
                }
            }
            // The read timeout is how a missing reply shows up; anything else is the
            // socket failing under us, which is also the end of this attempt.
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(IcmpError::Timeout)
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return Err(IcmpError::Permission),
            Err(_) => return Err(IcmpError::Socket),
        }
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    /// The whole point of telling the errors apart: the messages have to say which
    /// one it was, because the operator reads them instead of a log.
    #[test]
    fn each_failure_says_which_one_it_was() {
        assert!(IcmpError::Permission.to_string().contains("CAP_NET_RAW"));
        assert!(IcmpError::Timeout.to_string().contains("timeout"));
        assert_ne!(IcmpError::Permission, IcmpError::Timeout, "and they are not each other");
    }

    /// An IPv6 target is refused as an address problem, not reported as a loss: the
    /// v6 message shape is the next step, and a silent 100% loss would be read as a
    /// broken link.
    #[test]
    fn an_ipv6_target_is_refused_with_a_reason() {
        let v6: SocketAddr = "[2606:4700:4700::1111]:0".parse().unwrap();
        assert_eq!(ping_once(v6, Duration::from_millis(1)), Err(IcmpError::Address));
    }
}
