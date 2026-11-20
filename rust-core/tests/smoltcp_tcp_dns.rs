//! Host-side TCP DNS transport proof using two smoltcp interfaces.
//!
//! This test exercises a real TCP handshake, stream delivery, and bounded
//! TUN packet queues. It deliberately stops at the DNS message boundary:
//! no Android socket, VpnService.protect(), upstream exchange, JNI session,
//! or production VPN service is involved.

use firewalldns_native::TunPacketDevice;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

const CLIENT_IP: Ipv4Address = Ipv4Address::new(10, 88, 0, 2);
const SERVER_IP: Ipv4Address = Ipv4Address::new(10, 88, 0, 3);
const DNS_PORT: u16 = 53;
const CLIENT_PORT: u16 = 49152;

fn transfer_packets(from: &mut TunPacketDevice, to: &mut TunPacketDevice) {
    while let Some(packet) = from.dequeue_tx() {
        to.enqueue_rx(packet).expect("peer RX queue must accept packet");
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

    // Give ACKs and any immediately generated control packets another turn.
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
fn smoltcp_tcp_connection_delivers_split_and_coalesced_dns_frames() {
    let mut client_device = TunPacketDevice::new_with_byte_limits(1500, 32, 32, 48_000, 48_000);
    let mut server_device = TunPacketDevice::new_with_byte_limits(1500, 32, 32, 48_000, 48_000);

    let mut client_iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut client_device,
        Instant::from_millis(0),
    );
    client_iface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(IpAddress::Ipv4(CLIENT_IP), 24));
    });

    let mut server_iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut server_device,
        Instant::from_millis(0),
    );
    server_iface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(IpAddress::Ipv4(SERVER_IP), 24));
    });

    let server_rx = TcpSocketBuffer::new(vec![0; 4096]);
    let server_tx = TcpSocketBuffer::new(vec![0; 4096]);
    let mut server_sockets = SocketSet::new(vec![]);
    let server_handle = server_sockets.add(TcpSocket::new(server_rx, server_tx));
    server_sockets
        .get_mut::<TcpSocket>(server_handle)
        .listen(DNS_PORT)
        .expect("DNS TCP listener should bind");

    let client_rx = TcpSocketBuffer::new(vec![0; 4096]);
    let client_tx = TcpSocketBuffer::new(vec![0; 4096]);
    let mut client_sockets = SocketSet::new(vec![]);
    let client_handle = client_sockets.add(TcpSocket::new(client_rx, client_tx));

    let server_endpoint = IpEndpoint::new(IpAddress::Ipv4(SERVER_IP), DNS_PORT);
    let client_endpoint = IpEndpoint::new(IpAddress::Ipv4(CLIENT_IP), CLIENT_PORT);
    client_sockets
        .get_mut::<TcpSocket>(client_handle)
        .connect(client_iface.context(), server_endpoint, client_endpoint)
        .expect("TCP client should start connection");

    // Complete SYN/SYN-ACK/ACK through the two virtual TUN devices.
    let mut established = false;
    for tick in 1..=2000 {
        let now = Instant::from_millis(tick);
        pump(
            now,
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut server_iface,
            &mut server_device,
            &mut server_sockets,
        );
        if client_sockets.get::<TcpSocket>(client_handle).can_send()
            && server_sockets.get::<TcpSocket>(server_handle).can_recv()
                || (client_sockets.get::<TcpSocket>(client_handle).can_send()
                    && server_sockets.get::<TcpSocket>(server_handle).is_active())
        {
            established = true;
            break;
        }
    }
    assert!(established, "smoltcp TCP handshake must complete");
    assert_eq!(client_device.queued_tx(), 0);
    assert_eq!(server_device.queued_tx(), 0);

    let dns_query_one = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let dns_query_two = [
        0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let frame_one = dns_frame(&dns_query_one);
    let frame_two = dns_frame(&dns_query_two);
    let mut expected = frame_one.clone();
    expected.extend_from_slice(&frame_two);

    // Split the first length prefix/body across separate application writes.
    {
        let client = client_sockets.get_mut::<TcpSocket>(client_handle);
        client.send_slice(&frame_one[..1]).expect("send first prefix byte");
    }
    let mut received = Vec::with_capacity(expected.len());
    let mut scratch = [0u8; 64];
    let mut tick = 2001u64;
    for _ in 0..200 {
        pump(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut server_iface,
            &mut server_device,
            &mut server_sockets,
        );
        tick += 1;
        if let Ok(length) = server_sockets
            .get_mut::<TcpSocket>(server_handle)
            .recv_slice(&mut scratch)
        {
            received.extend_from_slice(&scratch[..length]);
            if !received.is_empty() {
                break;
            }
        }
    }
    assert_eq!(received, frame_one[..1]);

    {
        let client = client_sockets.get_mut::<TcpSocket>(client_handle);
        client
            .send_slice(&frame_one[1..])
            .expect("send remaining first DNS frame");
        client
            .send_slice(&frame_two)
            .expect("send second coalesced DNS frame");
    }

    for _ in 0..2000 {
        pump(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut server_iface,
            &mut server_device,
            &mut server_sockets,
        );
        tick += 1;
        if let Ok(length) = server_sockets
            .get_mut::<TcpSocket>(server_handle)
            .recv_slice(&mut scratch)
        {
            received.extend_from_slice(&scratch[..length]);
            if received.len() >= expected.len() {
                break;
            }
        }
    }

    assert_eq!(received, expected, "TCP must preserve the ordered DNS byte stream");
    assert_eq!(client_device.queued_tx(), 0);
    assert_eq!(server_device.queued_tx(), 0);
    assert_eq!(client_device.queued_rx_bytes(), 0);
    assert_eq!(server_device.queued_rx_bytes(), 0);
}
