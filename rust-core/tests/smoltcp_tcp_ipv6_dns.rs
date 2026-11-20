//! Host-side IPv6 TCP DNS transport proof using two smoltcp interfaces.
//!
//! Verifies an IPv6 TCP handshake and bidirectional DNS-over-TCP framing
//! over bounded virtual TUN queues. No Android, JNI, protected upstream
//! sockets, or production VPN service is involved.

use firewalldns_native::TunPacketDevice;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv6Address};

const CLIENT_IP: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const SERVER_IP: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
const DNS_PORT: u16 = 53;
const CLIENT_PORT: u16 = 49154;

fn make_interface(device: &mut TunPacketDevice, address: Ipv6Address) -> Interface {
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(IpAddress::Ipv6(address), 64));
    });
    interface
}

fn transfer_packets(from: &mut TunPacketDevice, to: &mut TunPacketDevice) {
    while let Some(packet) = from.dequeue_tx() {
        to.enqueue_rx(packet).expect("bounded peer RX queue accepts packet");
    }
}

fn pump(
    timestamp: Instant,
    client_iface: &mut Interface,
    client_device: &mut TunPacketDevice,
    client_sockets: &mut SocketSet<'_>,
    server_iface: &mut Interface,
    server_device: &mut TunPacketDevice,
    server_sockets: &mut SocketSet<'_>,
) {
    client_iface.poll(timestamp, client_device, client_sockets);
    transfer_packets(client_device, server_device);
    server_iface.poll(timestamp, server_device, server_sockets);
    transfer_packets(server_device, client_device);
    client_iface.poll(timestamp, client_device, client_sockets);
    transfer_packets(client_device, server_device);
}

fn dns_frame(message: &[u8]) -> Vec<u8> {
    assert!(!message.is_empty());
    assert!(message.len() <= u16::MAX as usize);
    let mut frame = Vec::with_capacity(2 + message.len());
    frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

#[test]
fn ipv6_tcp_dns_stream_completes_handshake_and_roundtrips_frames() {
    let mut client_device = TunPacketDevice::new_with_byte_limits(1500, 32, 32, 48_000, 48_000);
    let mut server_device = TunPacketDevice::new_with_byte_limits(1500, 32, 32, 48_000, 48_000);
    let mut client_iface = make_interface(&mut client_device, CLIENT_IP);
    let mut server_iface = make_interface(&mut server_device, SERVER_IP);

    let mut server_sockets = SocketSet::new(vec![]);
    let server_handle = server_sockets.add(TcpSocket::new(
        TcpSocketBuffer::new(vec![0; 4096]),
        TcpSocketBuffer::new(vec![0; 4096]),
    ));
    server_sockets.get_mut::<TcpSocket>(server_handle)
        .listen(DNS_PORT).expect("IPv6 DNS listener binds");

    let mut client_sockets = SocketSet::new(vec![]);
    let client_handle = client_sockets.add(TcpSocket::new(
        TcpSocketBuffer::new(vec![0; 4096]),
        TcpSocketBuffer::new(vec![0; 4096]),
    ));
    client_sockets.get_mut::<TcpSocket>(client_handle)
        .connect(
            client_iface.context(),
            IpEndpoint::new(IpAddress::Ipv6(SERVER_IP), DNS_PORT),
            IpEndpoint::new(IpAddress::Ipv6(CLIENT_IP), CLIENT_PORT),
        ).expect("IPv6 TCP connect starts");

    let mut established = false;
    for tick in 1..=3000 {
        pump(
            Instant::from_millis(tick), &mut client_iface, &mut client_device,
            &mut client_sockets, &mut server_iface, &mut server_device, &mut server_sockets,
        );
        if client_sockets.get::<TcpSocket>(client_handle).may_send()
            && server_sockets.get::<TcpSocket>(server_handle).may_recv()
        {
            established = true;
            break;
        }
    }
    assert!(established, "IPv6 TCP handshake must complete");

    let query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    let response = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    let query_frame = dns_frame(&query);
    let response_frame = dns_frame(&response);
    client_sockets.get_mut::<TcpSocket>(client_handle)
        .send_slice(&query_frame).expect("send DNS query frame");

    let mut tick = 3001i64;
    let mut scratch = [0u8; 64];
    let mut received_query = Vec::new();
    for _ in 0..2000 {
        pump(
            Instant::from_millis(tick), &mut client_iface, &mut client_device,
            &mut client_sockets, &mut server_iface, &mut server_device, &mut server_sockets,
        );
        tick += 1;
        if let Ok(length) = server_sockets.get_mut::<TcpSocket>(server_handle)
            .recv_slice(&mut scratch)
        {
            received_query.extend_from_slice(&scratch[..length]);
            if received_query.len() >= query_frame.len() { break; }
        }
    }
    assert_eq!(received_query, query_frame, "server receives exact DNS query frame");

    server_sockets.get_mut::<TcpSocket>(server_handle)
        .send_slice(&response_frame).expect("send DNS response frame");
    let mut received_response = Vec::new();
    for _ in 0..2000 {
        pump(
            Instant::from_millis(tick), &mut client_iface, &mut client_device,
            &mut client_sockets, &mut server_iface, &mut server_device, &mut server_sockets,
        );
        tick += 1;
        if let Ok(length) = client_sockets.get_mut::<TcpSocket>(client_handle)
            .recv_slice(&mut scratch)
        {
            received_response.extend_from_slice(&scratch[..length]);
            if received_response.len() >= response_frame.len() { break; }
        }
    }
    assert_eq!(received_response, response_frame, "client receives exact DNS response frame");
    assert_eq!(client_device.queued_tx(), 0);
    assert_eq!(server_device.queued_tx(), 0);
    assert_eq!(client_device.queued_rx_bytes(), 0);
    assert_eq!(server_device.queued_rx_bytes(), 0);
}
