//! Verifies inbound IPv4/UDP packets traverse the bounded TUN RX queue
//! and are delivered to the matching smoltcp UDP socket. Host-side only.

use firewalldns_native::TunPacketDevice;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(last) = bytes.chunks_exact(2).remainder().first() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn inbound_udp_packet(payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&1u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 77, 0, 3]);
    packet[16..20].copy_from_slice(&[10, 77, 0, 2]);
    packet[20..22].copy_from_slice(&443u16.to_be_bytes());
    packet[22..24].copy_from_slice(&53000u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    // A zero UDP checksum is valid for IPv4.
    packet[28..].copy_from_slice(payload);
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet
}

#[test]
fn inbound_udp_packet_reaches_matching_smoltcp_socket_from_tun_rx() {
    let mut device = TunPacketDevice::new(1500, 8, 8);
    let config = Config::new(HardwareAddress::Ip);
    let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
    interface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 2)),
            24,
        ));
    });

    let rx_buffer = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 512]);
    let tx_buffer = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 512]);
    let socket = UdpSocket::new(rx_buffer, tx_buffer);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(socket);
    sockets.get_mut::<UdpSocket>(handle).bind(53000).expect("bind UDP socket");

    let payload = b"firewalldns-inbound-udp";
    device.enqueue_rx(inbound_udp_packet(payload)).expect("enqueue TUN RX packet");
    assert_eq!(device.queued_rx(), 1);

    interface.poll(Instant::from_millis(1), &mut device, &mut sockets);

    let mut received = [0u8; 64];
    let (length, endpoint) = sockets
        .get_mut::<UdpSocket>(handle)
        .recv_slice(&mut received)
        .expect("smoltcp should deliver inbound datagram to bound socket");
    assert_eq!(&received[..length], payload);
    assert_eq!(length, payload.len());
    assert_eq!(endpoint.port, 443);
    assert_eq!(endpoint.addr, IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 3)));
    assert_eq!(device.queued_rx(), 0);
    assert_eq!(device.queued_rx_bytes(), 0);
}
