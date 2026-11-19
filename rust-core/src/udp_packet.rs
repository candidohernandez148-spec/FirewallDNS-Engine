//! Generic UDP packet preflight for the FirewallDNS transport foundation.
//!
//! This module validates complete, unfragmented IPv4/IPv6 UDP datagrams. It
//! does not open sockets, forward packets, own the TUN descriptor, or make
//! firewall decisions. DNS remains on its existing processing path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPacketError {
    Empty,
    UnsupportedIpVersion,
    TruncatedIpHeader,
    InvalidIpv4HeaderLength,
    InvalidIpv4HeaderChecksum,
    InvalidIpLength,
    FragmentedPacket,
    NotUdp,
    UnsupportedIpv6ExtensionHeader,
    TruncatedUdpHeader,
    InvalidUdpLength,
    MissingIpv6UdpChecksum,
    InvalidUdpChecksum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

/// Validate and decode one complete IPv4/IPv6 UDP packet.
///
/// IPv4 fragments and IPv6 extension headers are deliberately rejected until
/// reassembly/extension handling is implemented and tested by the stack layer.
pub fn parse_udp_packet(packet: &[u8]) -> Result<UdpDatagram<'_>, UdpPacketError> {
    let first = *packet.first().ok_or(UdpPacketError::Empty)?;
    match first >> 4 {
        4 => parse_ipv4_udp(packet),
        6 => parse_ipv6_udp(packet),
        _ => Err(UdpPacketError::UnsupportedIpVersion),
    }
}

fn parse_ipv4_udp(packet: &[u8]) -> Result<UdpDatagram<'_>, UdpPacketError> {
    if packet.len() < 20 {
        return Err(UdpPacketError::TruncatedIpHeader);
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if !(20..=60).contains(&header_len) || packet.len() < header_len {
        return Err(UdpPacketError::InvalidIpv4HeaderLength);
    }
    if checksum(&packet[..header_len]) != 0 {
        return Err(UdpPacketError::InvalidIpv4HeaderChecksum);
    }
    let total_len = read_u16(packet, 2) as usize;
    if total_len < header_len + 8 || total_len > packet.len() {
        return Err(UdpPacketError::InvalidIpLength);
    }
    if packet[9] != IPPROTO_UDP {
        return Err(UdpPacketError::NotUdp);
    }
    if read_u16(packet, 6) & 0x3fff != 0 {
        return Err(UdpPacketError::FragmentedPacket);
    }

    let udp = &packet[header_len..total_len];
    let udp_len = read_u16(udp, 4) as usize;
    if udp_len < 8 || udp_len != udp.len() {
        return Err(UdpPacketError::InvalidUdpLength);
    }
    let udp_checksum = read_u16(udp, 6);
    if udp_checksum != 0
        && checksum_ipv4_udp(&packet[12..16], &packet[16..20], udp) != 0
    {
        return Err(UdpPacketError::InvalidUdpChecksum);
    }

    Ok(UdpDatagram {
        source: IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
        destination: IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
        source_port: read_u16(udp, 0),
        destination_port: read_u16(udp, 2),
        payload: &udp[8..],
    })
}

fn parse_ipv6_udp(packet: &[u8]) -> Result<UdpDatagram<'_>, UdpPacketError> {
    if packet.len() < 40 {
        return Err(UdpPacketError::TruncatedIpHeader);
    }
    if packet[6] != IPPROTO_UDP {
        return Err(if matches!(packet[6], 0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140) {
            UdpPacketError::UnsupportedIpv6ExtensionHeader
        } else {
            UdpPacketError::NotUdp
        });
    }
    let payload_len = read_u16(packet, 4) as usize;
    let total_len = 40usize.checked_add(payload_len).ok_or(UdpPacketError::InvalidIpLength)?;
    if payload_len < 8 || total_len > packet.len() {
        return Err(UdpPacketError::InvalidIpLength);
    }
    let udp = &packet[40..total_len];
    let udp_len = read_u16(udp, 4) as usize;
    if udp_len < 8 || udp_len != udp.len() {
        return Err(UdpPacketError::InvalidUdpLength);
    }
    if read_u16(udp, 6) == 0 {
        return Err(UdpPacketError::MissingIpv6UdpChecksum);
    }
    if checksum_ipv6_udp(&packet[8..24], &packet[24..40], udp) != 0 {
        return Err(UdpPacketError::InvalidUdpChecksum);
    }

    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    Ok(UdpDatagram {
        source: IpAddr::V6(Ipv6Addr::from(source)),
        destination: IpAddr::V6(Ipv6Addr::from(destination)),
        source_port: read_u16(udp, 0),
        destination_port: read_u16(udp, 2),
        payload: &udp[8..],
    })
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

fn checksum_ipv4_udp(source: &[u8], destination: &[u8], udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(source);
    pseudo.extend_from_slice(destination);
    pseudo.extend_from_slice(&[0, IPPROTO_UDP]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    checksum(&pseudo)
}

fn checksum_ipv6_udp(source: &[u8], destination: &[u8], udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp.len());
    pseudo.extend_from_slice(source);
    pseudo.extend_from_slice(destination);
    pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, IPPROTO_UDP]);
    pseudo.extend_from_slice(udp);
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

    fn make_ipv4_udp(destination_port: u16, payload: &[u8], with_checksum: bool) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + 8 + payload.len()];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..22].copy_from_slice(&53000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        if with_checksum {
            let value = checksum_ipv4_udp(&packet[12..16], &packet[16..20], &packet[20..]);
            packet[26..28].copy_from_slice(&value.to_be_bytes());
        }
        let value = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
        packet
    }

    fn make_ipv6_udp(destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + 8 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[6] = IPPROTO_UDP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[24..40].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40..42].copy_from_slice(&53000u16.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
        let value = checksum_ipv6_udp(&packet[8..24], &packet[24..40], &packet[40..]);
        packet[46..48].copy_from_slice(&value.to_be_bytes());
        packet
    }

    #[test]
    fn parses_non_dns_udp_ipv4_without_changing_dns_path() {
        let payload = [1, 2, 3, 4];
        let packet = make_ipv4_udp(443, &payload, true);
        let decoded = parse_udp_packet(&packet).unwrap();
        assert_eq!(decoded.source_port, 53000);
        assert_eq!(decoded.destination_port, 443);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.source, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(decoded.destination, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_non_dns_udp_ipv6_with_required_checksum() {
        let payload = [9, 8, 7];
        let packet = make_ipv6_udp(443, &payload);
        let decoded = parse_udp_packet(&packet).unwrap();
        assert_eq!(decoded.destination_port, 443);
        assert_eq!(decoded.payload, payload);
        assert!(matches!(decoded.destination, IpAddr::V6(_)));
    }

    #[test]
    fn permits_zero_udp_checksum_only_for_ipv4() {
        assert!(parse_udp_packet(&make_ipv4_udp(443, &[1], false)).is_ok());
        let mut ipv6 = make_ipv6_udp(443, &[1]);
        ipv6[46..48].fill(0);
        assert_eq!(parse_udp_packet(&ipv6), Err(UdpPacketError::MissingIpv6UdpChecksum));
    }

    #[test]
    fn rejects_fragmented_ipv4_and_ipv6_extension_headers() {
        let mut ipv4 = make_ipv4_udp(443, &[1], false);
        ipv4[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        ipv4[10..12].fill(0);
        let value = checksum(&ipv4[..20]);
        ipv4[10..12].copy_from_slice(&value.to_be_bytes());
        assert_eq!(parse_udp_packet(&ipv4), Err(UdpPacketError::FragmentedPacket));

        let mut ipv6 = make_ipv6_udp(443, &[1]);
        ipv6[6] = 60;
        assert_eq!(parse_udp_packet(&ipv6), Err(UdpPacketError::UnsupportedIpv6ExtensionHeader));
    }

    #[test]
    fn rejects_bad_lengths_and_corrupt_udp_checksum() {
        let mut short = make_ipv4_udp(443, &[1, 2], false);
        short[24..26].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(parse_udp_packet(&short), Err(UdpPacketError::InvalidUdpLength));

        let mut corrupt = make_ipv6_udp(443, &[1, 2]);
        corrupt[48] ^= 0xff;
        assert_eq!(parse_udp_packet(&corrupt), Err(UdpPacketError::InvalidUdpChecksum));
    }

    #[test]
    fn rejects_non_udp_and_truncated_packets() {
        assert_eq!(parse_udp_packet(&[]), Err(UdpPacketError::Empty));
        assert_eq!(parse_udp_packet(&[0x45]), Err(UdpPacketError::TruncatedIpHeader));
        let mut packet = make_ipv4_udp(443, &[1], false);
        packet[9] = 6;
        packet[10..12].fill(0);
        let value = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
        assert_eq!(parse_udp_packet(&packet), Err(UdpPacketError::NotUdp));
    }
}
