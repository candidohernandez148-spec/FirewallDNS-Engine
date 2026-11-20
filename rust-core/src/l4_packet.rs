//! Unified IPv4/IPv6 TCP + UDP preflight for FirewallDNS.
//!
//! This parser validates complete unfragmented IP packets. It does not own a
//! TUN descriptor, create sockets, run a TCP state machine, or forward traffic.
//! The production Android VPN still uses its Kotlin packet path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketValidationResult {
    ValidUdp,
    ValidTcp,
    InvalidIpHeader,
    InvalidIpLength,
    UnsupportedProtocol,
    IpFragment,
    InvalidL4Length,
    InvalidL4Checksum,
    UnsupportedIpv6Extension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedTransportPacket<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub ip_header_len: usize,
    pub transport_header_len: usize,
    pub transport_len: usize,
    pub payload: &'a [u8],
}

impl ValidatedTransportPacket<'_> {
    pub fn is_tcp(&self) -> bool { self.protocol == IPPROTO_TCP }
    pub fn is_udp(&self) -> bool { self.protocol == IPPROTO_UDP }
}

/// Validates one complete IP packet and returns its checked TCP/UDP metadata.
///
/// IPv4 options are accepted after validating IHL and header checksum.
/// IPv4 fragments, IPv6 extension headers, IPv6 jumbograms and trailing bytes
/// beyond the declared IP length are rejected explicitly.
pub fn validate_tun_l4_packet(
    packet: &[u8],
) -> Result<ValidatedTransportPacket<'_>, PacketValidationResult> {
    let first = *packet.first().ok_or(PacketValidationResult::InvalidIpHeader)?;
    let version = first >> 4;

    let (ip_header_len, total_len, protocol, source, destination, ipv6) = match version {
        4 => {
            if packet.len() < 20 { return Err(PacketValidationResult::InvalidIpHeader); }
            let header_len = ((first & 0x0f) as usize) * 4;
            if !(20..=60).contains(&header_len) || packet.len() < header_len {
                return Err(PacketValidationResult::InvalidIpHeader);
            }
            let total_len = read_u16(packet, 2) as usize;
            if total_len != packet.len() || total_len < header_len {
                return Err(PacketValidationResult::InvalidIpLength);
            }
            if read_u16(packet, 6) & 0xbfff != 0 {
                return Err(PacketValidationResult::IpFragment);
            }
            if checksum(&packet[..header_len]) != 0 {
                return Err(PacketValidationResult::InvalidIpHeader);
            }
            let mut src = [0u8; 4];
            src.copy_from_slice(&packet[12..16]);
            let mut dst = [0u8; 4];
            dst.copy_from_slice(&packet[16..20]);
            (
                header_len,
                total_len,
                packet[9],
                IpAddr::V4(Ipv4Addr::from(src)),
                IpAddr::V4(Ipv4Addr::from(dst)),
                false,
            )
        }
        6 => {
            if packet.len() < 40 { return Err(PacketValidationResult::InvalidIpHeader); }
            let payload_len = read_u16(packet, 4) as usize;
            let total_len = 40usize.checked_add(payload_len)
                .ok_or(PacketValidationResult::InvalidIpLength)?;
            if payload_len == 0 || total_len != packet.len() {
                return Err(PacketValidationResult::InvalidIpLength);
            }
            let next_header = packet[6];
            if next_header == 44 { return Err(PacketValidationResult::IpFragment); }
            if is_ipv6_extension(next_header) {
                return Err(PacketValidationResult::UnsupportedIpv6Extension);
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&packet[8..24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&packet[24..40]);
            (
                40,
                total_len,
                next_header,
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                true,
            )
        }
        _ => return Err(PacketValidationResult::InvalidIpHeader),
    };

    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Err(PacketValidationResult::UnsupportedProtocol);
    }
    let transport_len = total_len - ip_header_len;
    let minimum = if protocol == IPPROTO_TCP { 20 } else { 8 };
    if transport_len < minimum {
        return Err(PacketValidationResult::InvalidL4Length);
    }
    let transport = &packet[ip_header_len..total_len];

    let transport_header_len = if protocol == IPPROTO_TCP {
        let header_len = ((transport[12] >> 4) as usize) * 4;
        if !(20..=transport_len).contains(&header_len) {
            return Err(PacketValidationResult::InvalidL4Length);
        }
        if transport_checksum(ipv6, &packet[ip_header_len..total_len], source, destination, protocol) != 0 {
            return Err(PacketValidationResult::InvalidL4Checksum);
        }
        header_len
    } else {
        let udp_len = read_u16(transport, 4) as usize;
        if udp_len < 8 || udp_len != transport_len {
            return Err(PacketValidationResult::InvalidL4Length);
        }
        let udp_checksum = read_u16(transport, 6);
        if ipv6 && udp_checksum == 0 {
            return Err(PacketValidationResult::InvalidL4Checksum);
        }
        if udp_checksum != 0
            && transport_checksum(ipv6, transport, source, destination, protocol) != 0
        {
            return Err(PacketValidationResult::InvalidL4Checksum);
        }
        8
    };

    Ok(ValidatedTransportPacket {
        source,
        destination,
        protocol,
        source_port: read_u16(transport, 0),
        destination_port: read_u16(transport, 2),
        ip_header_len,
        transport_header_len,
        transport_len,
        payload: &transport[transport_header_len..],
    })
}

fn is_ipv6_extension(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 50 | 51 | 60 | 135 | 139 | 140)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u64;
    }
    if let Some(last) = chunks.remainder().first() {
        sum += (*last as u64) << 8;
    }
    fold_checksum(sum)
}

fn transport_checksum(
    ipv6: bool,
    transport: &[u8],
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + transport.len());
    match (source, destination, ipv6) {
        (IpAddr::V4(src), IpAddr::V4(dst), false) => {
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&[0, protocol]);
            pseudo.extend_from_slice(&(transport.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst), true) => {
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&(transport.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, protocol]);
        }
        _ => return 0xffff,
    }
    pseudo.extend_from_slice(transport);
    checksum(&pseudo)
}

fn fold_checksum(mut sum: u64) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(ipv6: bool, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let ip_len = if ipv6 { 40 } else { 20 };
        let l4_len = if protocol == IPPROTO_TCP { 20 } else { 8 };
        let mut packet = vec![0u8; ip_len + l4_len + payload.len()];
        if ipv6 {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&((l4_len + payload.len()) as u16).to_be_bytes());
            packet[6] = protocol;
            packet[7] = 64;
            packet[8] = 0xfd;
            packet[23] = 2;
            packet[24] = 0xfd;
            packet[39] = 1;
        } else {
            packet[0] = 0x45;
            let total = packet.len() as u16;
            packet[2..4].copy_from_slice(&total.to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = protocol;
            packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
            packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        }
        let l4 = ip_len;
        packet[l4..l4 + 2].copy_from_slice(&53000u16.to_be_bytes());
        packet[l4 + 2..l4 + 4].copy_from_slice(&53u16.to_be_bytes());
        if protocol == IPPROTO_TCP {
            packet[l4 + 4..l4 + 8].copy_from_slice(&7u32.to_be_bytes());
            packet[l4 + 12] = 0x50;
            packet[l4 + 13] = 0x02;
            packet[l4 + 14..l4 + 16].copy_from_slice(&4096u16.to_be_bytes());
        } else {
            packet[l4 + 4..l4 + 6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        }
        packet[l4 + l4_len..].copy_from_slice(payload);

        {
            let source = if ipv6 {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()))
            } else {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap()))
            };
            let destination = if ipv6 {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()))
            } else {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap()))
            };
            let value = transport_checksum(ipv6, &packet[l4..], source, destination, protocol);
            let checksum_offset = l4 + if protocol == IPPROTO_TCP { 16 } else { 6 };
            packet[checksum_offset..checksum_offset + 2].copy_from_slice(&value.to_be_bytes());
        }
        if !ipv6 {
            let value = checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&value.to_be_bytes());
        }
        packet
    }

    #[test]
    fn validates_ipv4_tcp_and_ipv6_tcp() {
        let v4 = make_packet(false, IPPROTO_TCP, &[1, 2, 3]);
        let parsed4 = validate_tun_l4_packet(&v4).unwrap();
        assert!(parsed4.is_tcp());
        assert_eq!(parsed4.destination_port, 53);
        assert_eq!(parsed4.payload, &[1, 2, 3]);

        let v6 = make_packet(true, IPPROTO_TCP, &[4, 5]);
        assert!(validate_tun_l4_packet(&v6).unwrap().is_tcp());
    }

    #[test]
    fn validates_ipv4_udp_without_checksum_and_ipv6_udp_with_checksum() {
        let mut v4 = make_packet(false, IPPROTO_UDP, &[1, 2]);
        v4[26..28].fill(0);
        let checksum_value = checksum(&v4[..20]);
        v4[10..12].copy_from_slice(&checksum_value.to_be_bytes());
        assert!(validate_tun_l4_packet(&v4).unwrap().is_udp());

        let v6 = make_packet(true, IPPROTO_UDP, &[3, 4]);
        assert!(validate_tun_l4_packet(&v6).unwrap().is_udp());
        let mut no_checksum = v6;
        no_checksum[46..48].fill(0);
        assert_eq!(
            validate_tun_l4_packet(&no_checksum),
            Err(PacketValidationResult::InvalidL4Checksum)
        );
    }

    #[test]
    fn rejects_bad_tcp_header_length_checksum_and_ipv4_fragment() {
        let mut bad_offset = make_packet(false, IPPROTO_TCP, &[]);
        bad_offset[32] = 0x40;
        bad_offset[10..12].fill(0);
        let value = checksum(&bad_offset[..20]);
        bad_offset[10..12].copy_from_slice(&value.to_be_bytes());
        assert_eq!(
            validate_tun_l4_packet(&bad_offset),
            Err(PacketValidationResult::InvalidL4Length)
        );

        let mut bad_checksum = make_packet(false, IPPROTO_TCP, &[]);
        bad_checksum[36] ^= 1;
        assert_eq!(
            validate_tun_l4_packet(&bad_checksum),
            Err(PacketValidationResult::InvalidL4Checksum)
        );

        let mut fragment = make_packet(false, IPPROTO_TCP, &[]);
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        fragment[10..12].fill(0);
        let value = checksum(&fragment[..20]);
        fragment[10..12].copy_from_slice(&value.to_be_bytes());
        assert_eq!(
            validate_tun_l4_packet(&fragment),
            Err(PacketValidationResult::IpFragment)
        );
    }

    #[test]
    fn rejects_ipv6_extension_and_declared_length_mismatch() {
        let mut extension = make_packet(true, IPPROTO_TCP, &[]);
        extension[6] = 60;
        assert_eq!(
            validate_tun_l4_packet(&extension),
            Err(PacketValidationResult::UnsupportedIpv6Extension)
        );

        let mut short = make_packet(false, IPPROTO_TCP, &[]);
        let declared_len = (short.len() - 1) as u16;
        short[2..4].copy_from_slice(&declared_len.to_be_bytes());
        assert_eq!(
            validate_tun_l4_packet(&short),
            Err(PacketValidationResult::InvalidIpLength)
        );
    }
}
