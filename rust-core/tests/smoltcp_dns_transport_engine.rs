//! End-to-end host tests for the stateful smoltcp DNS/TCP transport.
//! These tests exercise the transport owner and virtual TUN queues, not Android
//! JNI, VpnService.protect(), real upstream sockets, or the production service.

use firewalldns_native::{TcpDnsEvent, TcpDnsTransport, TunPacketDevice};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address,
};

const CLIENT_V4: Ipv4Address = Ipv4Address::new(10, 88, 0, 2);
const SERVER_V4: Ipv4Address = Ipv4Address::new(10, 88, 0, 3);
const CLIENT_V6: Ipv6Address = Ipv6Address::new(0xfd88, 0, 0, 0, 0, 0, 0, 2);
const SERVER_V6: Ipv6Address = Ipv6Address::new(0xfd88, 0, 0, 0, 0, 0, 0, 3);
const CLIENT_PORT: u16 = 49153;
const DNS_PORT: u16 = 53;

fn make_client_v4(device: &mut TunPacketDevice) -> Interface {
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        device,
        Instant::ZERO,
    );
    iface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(IpAddress::Ipv4(CLIENT_V4), 24));
    });
    iface
}

fn make_client_v6(device: &mut TunPacketDevice) -> Interface {
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        device,
        Instant::ZERO,
    );
    iface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(IpAddress::Ipv6(CLIENT_V6), 64));
    });
    iface
}

fn pump_v4(
    now: Instant,
    client_iface: &mut Interface,
    client_device: &mut TunPacketDevice,
    client_sockets: &mut SocketSet<'_>,
    engine: &mut TcpDnsTransport,
) {
    client_iface.poll(now, client_device, client_sockets);
    while let Some(packet) = client_device.dequeue_tx() {
        engine.enqueue_packet(packet, now).expect("engine ingress queue accepts client packet");
    }
    engine.poll(now, 32);
    while let Some(packet) = engine.take_packet() {
        client_device.enqueue_rx(packet).expect("client RX queue accepts engine packet");
    }
    client_iface.poll(now, client_device, client_sockets);
}

fn pump_v6(
    now: Instant,
    client_iface: &mut Interface,
    client_device: &mut TunPacketDevice,
    client_sockets: &mut SocketSet<'_>,
    engine: &mut TcpDnsTransport,
) {
    client_iface.poll(now, client_device, client_sockets);
    while let Some(packet) = client_device.dequeue_tx() {
        engine.enqueue_packet(packet, now).expect("engine ingress queue accepts client packet");
    }
    engine.poll(now, 32);
    while let Some(packet) = engine.take_packet() {
        client_device.enqueue_rx(packet).expect("client RX queue accepts engine packet");
    }
    client_iface.poll(now, client_device, client_sockets);
}

fn frame_dns(message: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + message.len());
    frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

fn query(id: u8) -> Vec<u8> {
    vec![id, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
}

fn response(id: u8) -> Vec<u8> {
    vec![id, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]
}

#[test]
fn ipv4_tcp_dns_handshake_stream_event_and_response_roundtrip() {
    let mut client_device = TunPacketDevice::new_with_byte_limits(1500, 32, 32, 48_000, 48_000);
    let mut client_iface = make_client_v4(&mut client_device);
    let mut client_sockets = SocketSet::new(vec![]);
    let client_handle = client_sockets.add(TcpSocket::new(
        SocketBuffer::new(vec![0; 8192]),
        SocketBuffer::new(vec![0; 8192]),
    ));
    let mut engine = TcpDnsTransport::new(1500, SERVER_V4, CLIENT_V4, SERVER_V6, CLIENT_V6, 8).unwrap();

    client_sockets.get_mut::<TcpSocket>(client_handle)
        .connect(
            client_iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(SERVER_V4), DNS_PORT),
            IpEndpoint::new(IpAddress::Ipv4(CLIENT_V4), CLIENT_PORT),
        )
        .expect("client TCP connect starts");

    let mut opened = None;
    for tick in 1..=3000 {
        pump_v4(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut engine,
        );
        while let Some(event) = engine.take_event() {
            if let TcpDnsEvent::SessionOpened { session_id, flow } = event {
                assert_eq!(flow.client_ip, std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 88, 0, 2)));
                assert_eq!(flow.server_ip, std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 88, 0, 3)));
                assert_eq!(flow.client_port, CLIENT_PORT);
                assert_eq!(flow.server_port, DNS_PORT);
                opened = Some(session_id);
            }
        }
        if opened.is_some() && client_sockets.get::<TcpSocket>(client_handle).may_send() {
            break;
        }
    }
    let session_id = opened.expect("smoltcp engine must emit an established IPv4 session");
    assert_eq!(engine.active_sessions(), 1);

    let query_frame = frame_dns(&query(0x12));
    client_sockets.get_mut::<TcpSocket>(client_handle)
        .send_slice(&query_frame)
        .expect("client sends framed DNS query");

    let mut data = Vec::new();
    for tick in 3001..=5000 {
        pump_v4(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut engine,
        );
        while let Some(event) = engine.take_event() {
            if let TcpDnsEvent::Data { session_id: id, bytes } = event {
                assert_eq!(id, session_id);
                data.extend_from_slice(&bytes);
            }
        }
        if data.len() >= query_frame.len() {
            break;
        }
    }
    assert_eq!(data, query_frame, "engine must preserve exact DNS/TCP bytes");

    let response_frame = frame_dns(&response(0x12));
    engine.queue_response(session_id, response_frame.clone()).unwrap();
    assert!(!engine.close_session(session_id, false), "FIN must wait until queued DNS response bytes enter the TCP send buffer");
    let mut received = Vec::new();
    for tick in 5001..=7000 {
        pump_v4(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut engine,
        );
        let mut scratch = [0u8; 128];
        if let Ok(length) = client_sockets.get_mut::<TcpSocket>(client_handle).recv_slice(&mut scratch) {
            received.extend_from_slice(&scratch[..length]);
        }
        if received.len() >= response_frame.len() {
            break;
        }
    }
    assert_eq!(received, response_frame, "engine must return exact framed DNS response");
    assert!(engine.close_session(session_id, false), "FIN may follow after the response queue drains");
}

#[test]
fn ipv6_tcp_dns_handshake_and_stream_delivery() {
    let mut client_device = TunPacketDevice::new_with_byte_limits(1500, 32, 32, 48_000, 48_000);
    let mut client_iface = make_client_v6(&mut client_device);
    let mut client_sockets = SocketSet::new(vec![]);
    let client_handle = client_sockets.add(TcpSocket::new(
        SocketBuffer::new(vec![0; 8192]),
        SocketBuffer::new(vec![0; 8192]),
    ));
    let mut engine = TcpDnsTransport::new(1500, SERVER_V4, CLIENT_V4, SERVER_V6, CLIENT_V6, 8).unwrap();

    client_sockets.get_mut::<TcpSocket>(client_handle)
        .connect(
            client_iface.context(),
            IpEndpoint::new(IpAddress::Ipv6(SERVER_V6), DNS_PORT),
            IpEndpoint::new(IpAddress::Ipv6(CLIENT_V6), CLIENT_PORT),
        )
        .expect("IPv6 client TCP connect starts");

    let mut opened = None;
    for tick in 1..=4000 {
        pump_v6(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut engine,
        );
        while let Some(event) = engine.take_event() {
            if let TcpDnsEvent::SessionOpened { session_id, flow } = event {
                assert_eq!(flow.client_ip, std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xfd88, 0, 0, 0, 0, 0, 0, 2)));
                assert_eq!(flow.server_ip, std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xfd88, 0, 0, 0, 0, 0, 0, 3)));
                opened = Some(session_id);
            }
        }
        if opened.is_some() && client_sockets.get::<TcpSocket>(client_handle).may_send() {
            break;
        }
    }
    let session_id = opened.expect("smoltcp engine must emit an established IPv6 session");

    let query_frame = frame_dns(&query(0x56));
    client_sockets.get_mut::<TcpSocket>(client_handle)
        .send_slice(&query_frame)
        .expect("IPv6 client sends DNS query");
    let mut data = Vec::new();
    for tick in 4001..=6000 {
        pump_v6(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut engine,
        );
        while let Some(event) = engine.take_event() {
            if let TcpDnsEvent::Data { session_id: id, bytes } = event {
                assert_eq!(id, session_id);
                data.extend_from_slice(&bytes);
            }
        }
        if data.len() >= query_frame.len() {
            break;
        }
    }
    assert_eq!(data, query_frame);
}
