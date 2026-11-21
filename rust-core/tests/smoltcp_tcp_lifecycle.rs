//! Host-side TCP lifecycle checks for the FirewallDNS smoltcp laboratory.
//!
//! Covers retransmission after a dropped SYN and orderly/abortive teardown.
//! This does not connect smoltcp to Android, JNI, protected upstream sockets,
//! or the production VPN service.

use firewalldns_native::TunPacketDevice;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

const CLIENT_IP: Ipv4Address = Ipv4Address::new(10, 89, 0, 2);
const SERVER_IP: Ipv4Address = Ipv4Address::new(10, 89, 0, 3);
const DNS_PORT: u16 = 53;
const CLIENT_PORT: u16 = 49153;

fn make_interface(device: &mut TunPacketDevice, address: Ipv4Address) -> Interface {
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        device,
        Instant::from_millis(0),
    );
    interface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(IpAddress::Ipv4(address), 24));
    });
    interface
}

fn transfer_packets(from: &mut TunPacketDevice, to: &mut TunPacketDevice) {
    while let Some(packet) = from.dequeue_tx() {
        to.enqueue_rx(packet).expect("bounded peer RX queue accepts test packet");
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

fn establish_pair() -> (
    TunPacketDevice,
    Interface,
    SocketSet<'static>,
    smoltcp::iface::SocketHandle,
    TunPacketDevice,
    Interface,
    SocketSet<'static>,
    smoltcp::iface::SocketHandle,
) {
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
        .listen(DNS_PORT)
        .expect("DNS listener binds");

    let mut client_sockets = SocketSet::new(vec![]);
    let client_handle = client_sockets.add(TcpSocket::new(
        TcpSocketBuffer::new(vec![0; 4096]),
        TcpSocketBuffer::new(vec![0; 4096]),
    ));
    client_sockets.get_mut::<TcpSocket>(client_handle)
        .connect(
            client_iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(SERVER_IP), DNS_PORT),
            IpEndpoint::new(IpAddress::Ipv4(CLIENT_IP), CLIENT_PORT),
        )
        .expect("TCP connect starts");

    for tick in 1..=2000 {
        pump(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut server_iface,
            &mut server_device,
            &mut server_sockets,
        );
        if client_sockets.get::<TcpSocket>(client_handle).may_send()
            && server_sockets.get::<TcpSocket>(server_handle).may_recv()
        {
            return (
                client_device, client_iface, client_sockets, client_handle,
                server_device, server_iface, server_sockets, server_handle,
            );
        }
    }
    panic!("TCP handshake did not complete");
}

#[test]
fn retransmits_syn_when_the_first_syn_packet_is_dropped() {
    let mut device = TunPacketDevice::new_with_byte_limits(1500, 16, 16, 24_000, 24_000);
    let mut interface = make_interface(&mut device, CLIENT_IP);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(TcpSocket::new(
        TcpSocketBuffer::new(vec![0; 2048]),
        TcpSocketBuffer::new(vec![0; 2048]),
    ));
    sockets.get_mut::<TcpSocket>(handle)
        .connect(
            interface.context(),
            IpEndpoint::new(IpAddress::Ipv4(SERVER_IP), DNS_PORT),
            IpEndpoint::new(IpAddress::Ipv4(CLIENT_IP), CLIENT_PORT),
        )
        .expect("TCP connect starts");

    interface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    assert!(device.dequeue_tx().is_some(), "initial SYN must be emitted and deliberately dropped");

    let mut retransmitted = false;
    for tick in 2..=10_000 {
        interface.poll(Instant::from_millis(tick), &mut device, &mut sockets);
        if device.dequeue_tx().is_some() {
            retransmitted = true;
            break;
        }
    }
    assert!(retransmitted, "smoltcp must retransmit the SYN after packet loss");
}

#[test]
fn graceful_close_and_abortive_reset_release_both_tcp_sockets() {
    let (
        mut client_device, mut client_iface, mut client_sockets, client_handle,
        mut server_device, mut server_iface, mut server_sockets, server_handle,
    ) = establish_pair();

    client_sockets.get_mut::<TcpSocket>(client_handle).close();
    let mut peer_observed_fin = false;
    for tick in 2001..=5000 {
        pump(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut server_iface,
            &mut server_device,
            &mut server_sockets,
        );
        if !server_sockets.get::<TcpSocket>(server_handle).may_recv() {
            peer_observed_fin = true;
            break;
        }
    }
    assert!(peer_observed_fin, "peer must observe the graceful FIN");
    server_sockets.get_mut::<TcpSocket>(server_handle).close();

    let mut client_closed = false;
    for tick in 5001..=8000 {
        pump(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut server_iface,
            &mut server_device,
            &mut server_sockets,
        );
        if !client_sockets.get::<TcpSocket>(client_handle).is_active() {
            client_closed = true;
            break;
        }
    }
    assert!(client_closed, "client socket must leave the active state after close");

    let (
        mut client_device, mut client_iface, mut client_sockets, client_handle,
        mut server_device, mut server_iface, mut server_sockets, server_handle,
    ) = establish_pair();

    client_sockets.get_mut::<TcpSocket>(client_handle).abort();
    for tick in 2001..=2200 {
        pump(
            Instant::from_millis(tick),
            &mut client_iface,
            &mut client_device,
            &mut client_sockets,
            &mut server_iface,
            &mut server_device,
            &mut server_sockets,
        );
        if !server_sockets.get::<TcpSocket>(server_handle).is_active() {
            break;
        }
    }
    assert!(
        !server_sockets.get::<TcpSocket>(server_handle).is_active(),
        "peer socket must be released after receiving the abortive RST"
    );
}
