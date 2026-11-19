//! Integration proof that smoltcp UDP sockets can run over the bounded
//! in-memory TUN device. This is deliberately a host-side test harness:
//! it does not open Android sockets, call VpnService.protect(), or activate
//! the experimental stack in the production VPN path.

use firewalldns_native::{parse_udp_packet, TunPacketDevice};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

#[test]
fn smoltcp_udp_socket_emits_valid_packet_through_bounded_tun_device() {
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

    {
        let socket = sockets.get_mut::<UdpSocket>(handle);
        socket.bind(53000).expect("bind local UDP socket");
        socket
            .send_slice(
                b"firewalldns-udp-probe",
                IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 3)), 443),
            )
            .expect("queue UDP datagram");
    }

    interface.poll(Instant::from_millis(1), &mut device, &mut sockets);

    let packet = device
        .dequeue_tx()
        .expect("smoltcp should emit one packet into the TUN TX queue");
    let datagram = parse_udp_packet(&packet).expect("emitted packet must be valid UDP");
    assert_eq!(datagram.source, "10.77.0.2".parse().unwrap());
    assert_eq!(datagram.destination, "10.77.0.3".parse().unwrap());
    assert_eq!(datagram.source_port, 53000);
    assert_eq!(datagram.destination_port, 443);
    assert_eq!(datagram.payload, b"firewalldns-udp-probe");
    assert_eq!(device.queued_tx(), 0);
}
