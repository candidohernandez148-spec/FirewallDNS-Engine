//! Host-side round-trip harness for the FirewallDNS smoltcp UDP boundary.
//!
//! This test substitutes a loopback UDP socket for Android's protected socket.
//! It proves packet extraction, UDP payload transport, response reinjection and
//! smoltcp socket delivery, but does not prove VpnService.protect() or TUN I/O.

use firewalldns_native::{parse_udp_packet, TunPacketDevice};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as SmoltcpUdpSocket};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use std::net::{SocketAddr, UdpSocket as HostUdpSocket};
use std::thread;
use std::time::Duration;

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

fn inbound_ipv4_udp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&2u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 77, 0, 3]);
    packet[16..20].copy_from_slice(&[10, 77, 0, 2]);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    // A zero UDP checksum is permitted for IPv4.
    packet[28..].copy_from_slice(payload);
    let value = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&value.to_be_bytes());
    packet
}

#[test]
fn smoltcp_udp_packet_round_trips_through_host_loopback_socket() {
    let peer = HostUdpSocket::bind("127.0.0.1:0").expect("bind loopback UDP peer");
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let peer_addr: SocketAddr = peer.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut buffer = [0u8; 128];
        let (length, remote) = peer.recv_from(&mut buffer).expect("receive outbound datagram");
        assert_eq!(&buffer[..length], b"firewalldns-roundtrip-request");
        peer.send_to(b"firewalldns-roundtrip-response", remote)
            .expect("send loopback response");
    });

    let host_client = HostUdpSocket::bind("127.0.0.1:0").expect("bind host UDP client");
    host_client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let mut device = TunPacketDevice::new(1500, 8, 8);
    let config = Config::new(HardwareAddress::Ip);
    let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
    interface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 2)),
            24,
        ));
    });

    let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 512]);
    let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 512]);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(SmoltcpUdpSocket::new(rx, tx));
    {
        let socket = sockets.get_mut::<SmoltcpUdpSocket>(handle);
        socket.bind(53000).expect("bind smoltcp UDP socket");
        socket.send_slice(
            b"firewalldns-roundtrip-request",
            IpEndpoint::new(
                IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 3)),
                peer_addr.port(),
            ),
        ).expect("queue smoltcp datagram");
    }

    interface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    let outbound_packet = device.dequeue_tx().expect("smoltcp TX packet");
    let outbound = parse_udp_packet(&outbound_packet).expect("valid outbound UDP packet");
    assert_eq!(outbound.source_port, 53000);
    assert_eq!(outbound.destination_port, peer_addr.port());
    assert_eq!(outbound.payload, b"firewalldns-roundtrip-request");

    host_client.send_to(outbound.payload, peer_addr).expect("send via loopback peer");
    let mut response_buffer = [0u8; 128];
    let (response_len, _) = host_client.recv_from(&mut response_buffer)
        .expect("receive loopback response");
    server.join().expect("loopback server thread");
    let response = &response_buffer[..response_len];
    assert_eq!(response, b"firewalldns-roundtrip-response");

    device.enqueue_rx(inbound_ipv4_udp(peer_addr.port(), 53000, response))
        .expect("inject response into bounded TUN RX queue");
    interface.poll(Instant::from_millis(2), &mut device, &mut sockets);

    let mut delivered = [0u8; 128];
    let (length, endpoint) = sockets.get_mut::<SmoltcpUdpSocket>(handle)
        .recv_slice(&mut delivered)
        .expect("smoltcp must deliver reinjected response");
    assert_eq!(&delivered[..length], response);
    assert_eq!(endpoint.endpoint.port, peer_addr.port());
    assert_eq!(
        endpoint.endpoint.addr,
        IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 3)),
    );
    assert_eq!(device.queued_rx(), 0);
    assert_eq!(device.queued_rx_bytes(), 0);
    assert_eq!(device.queued_tx(), 0);
}
