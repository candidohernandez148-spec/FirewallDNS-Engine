//! Experimental native packet preflight for FirewallDNS.
//!
//! This crate validates only unfragmented UDP DNS packets carried directly by
//! IPv4 or IPv6. It is not a TCP/IP stack and does not make policy decisions.
//! Kotlin remains the production authority until parity and device benchmarks
//! justify a measured migration.

mod tun_device;
mod udp_packet;

pub use tun_device::{TunPacketDevice, TunQueueError};
pub use udp_packet::{parse_udp_packet, UdpDatagram, UdpPacketError};

use jni::objects::{JByteArray, JObject};
use jni::sys::jint;
use jni::JNIEnv;

const DNS_PORT: u16 = 53;
const IPPROTO_UDP: u8 = 17;
const INVALID: jint = 0;
const IPV4: jint = 4;
const IPV6: jint = 6;
const JNI_ERROR: jint = -1;

/// Returns 4 for a valid IPv4/UDP/DNS packet, 6 for IPv6, or 0 if unsupported.
pub fn validate_dns_udp_packet(packet: &[u8]) -> jint {
    if packet.is_empty() { return INVALID; }
    match packet[0] >> 4 {
        4 => if validate_ipv4(packet) { IPV4 } else { INVALID },
        6 => if validate_ipv6(packet) { IPV6 } else { INVALID },
        _ => INVALID,
    }
}

fn validate_ipv4(packet: &[u8]) -> bool {
    if packet.len() < 28 { return false; }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if !(20..=60).contains(&ihl) || ihl + 8 + 12 > packet.len() { return false; }
    if packet[9] != IPPROTO_UDP || checksum(&packet[..ihl]) != 0 { return false; }
    let total_len = read_u16(packet, 2) as usize;
    if total_len < ihl + 8 + 12 || total_len > packet.len() { return false; }
    let fragment = read_u16(packet, 6);
    if fragment & 0x3fff != 0 { return false; } // Reject MF and non-zero offset; allow DF.
    let udp_offset = ihl;
    let udp_len = read_u16(packet, udp_offset + 4) as usize;
    if udp_len < 8 + 12 || udp_len != total_len - ihl { return false; }
    if read_u16(packet, udp_offset + 2) != DNS_PORT { return false; }
    let udp_checksum = read_u16(packet, udp_offset + 6);
    udp_checksum == 0
        || checksum_ipv4_udp(&packet[12..16], &packet[16..20], &packet[udp_offset..total_len]) == 0
}

fn validate_ipv6(packet: &[u8]) -> bool {
    if packet.len() < 40 + 8 + 12 || packet[6] != IPPROTO_UDP {
        return false; // Extension headers are intentionally unsupported in this first slice.
    }
    let payload_len = read_u16(packet, 4) as usize;
    if payload_len < 8 + 12 || 40 + payload_len > packet.len() { return false; }
    let udp_offset = 40;
    let udp_len = read_u16(packet, udp_offset + 4) as usize;
    if udp_len < 8 + 12 || udp_len != payload_len { return false; }
    if read_u16(packet, udp_offset + 2) != DNS_PORT || read_u16(packet, udp_offset + 6) == 0 {
        return false; // UDP checksum is mandatory for IPv6.
    }
    checksum_ipv6_udp(
        &packet[8..24], &packet[24..40], &packet[udp_offset..udp_offset + udp_len],
    ) == 0
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks { sum += u16::from_be_bytes([pair[0], pair[1]]) as u64; }
    if let Some(last) = chunks.remainder().first() { sum += (*last as u64) << 8; }
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
    while (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

/// JNI bridge used only by the Android comparison harness.
#[no_mangle]
pub extern "system" fn Java_com_firewalldns_engine_android_NativePacketCore_nativeValidateDnsUdpPacket<'local>(
    mut env: JNIEnv<'local>,
    _receiver: JObject<'local>,
    packet: JByteArray<'local>,
    length: jint,
) -> jint {
    if length < 0 { return INVALID; }
    let bytes = match env.convert_byte_array(&packet) {
        Ok(bytes) => bytes,
        Err(_) => return JNI_ERROR,
    };
    let requested = length as usize;
    if requested > bytes.len() { return INVALID; }
    validate_dns_udp_packet(&bytes[..requested])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_query() -> Vec<u8> {
        let dns = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut packet = vec![0u8; 20 + 8 + dns.len()];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..22].copy_from_slice(&53000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&DNS_PORT.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        packet[28..].copy_from_slice(&dns);
        let header_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    fn make_ipv6_query() -> Vec<u8> {
        let dns = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut packet = vec![0u8; 40 + 8 + dns.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        packet[6] = IPPROTO_UDP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[24..40].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40..42].copy_from_slice(&53000u16.to_be_bytes());
        packet[42..44].copy_from_slice(&DNS_PORT.to_be_bytes());
        packet[44..46].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        packet[48..].copy_from_slice(&dns);
        let udp_checksum = checksum_ipv6_udp(&packet[8..24], &packet[24..40], &packet[40..]);
        packet[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
        packet
    }

    #[test]
    fn accepts_valid_ipv4_dns_udp() {
        assert_eq!(validate_dns_udp_packet(&make_ipv4_query()), IPV4);
    }

    #[test]
    fn accepts_valid_ipv6_dns_udp_with_mandatory_checksum() {
        assert_eq!(validate_dns_udp_packet(&make_ipv6_query()), IPV6);
    }

    #[test]
    fn rejects_truncated_and_non_dns_packets() {
        assert_eq!(validate_dns_udp_packet(&[0x45]), INVALID);
        let mut packet = make_ipv4_query();
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(validate_dns_udp_packet(&packet), INVALID);
    }

    #[test]
    fn rejects_ipv4_fragments_and_bad_header_checksum() {
        let mut fragment = make_ipv4_query();
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        fragment[10..12].fill(0);
        let checksum_value = checksum(&fragment[..20]);
        fragment[10..12].copy_from_slice(&checksum_value.to_be_bytes());
        assert_eq!(validate_dns_udp_packet(&fragment), INVALID);
        let mut corrupt = make_ipv4_query();
        corrupt[8] ^= 1;
        assert_eq!(validate_dns_udp_packet(&corrupt), INVALID);
    }

    #[test]
    fn rejects_ipv6_zero_udp_checksum() {
        let mut packet = make_ipv6_query();
        packet[46..48].fill(0);
        assert_eq!(validate_dns_udp_packet(&packet), INVALID);
    }
}
