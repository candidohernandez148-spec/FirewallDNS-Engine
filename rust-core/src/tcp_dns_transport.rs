//! Stateful DNS-over-TCP server transport backed by smoltcp 0.14.
//!
//! Ownership contract: one thread owns this value and is the only thread that
//! may call poll, take_event, queue_response, close_session, or take_packet.
//! TUN reader threads must hand packets to that owner through a separate
//! bounded queue. This module never opens upstream sockets and never performs
//! Android/JNI calls.
//!
//! Only complete, unfragmented IPv4/IPv6 TCP packets with a directly visible
//! TCP header are eligible for listener creation. smoltcp validates and
//! processes the actual TCP state machine and packet checksums.

use crate::{validate_tun_l4_packet, TunPacketDevice, TunQueueError};
use smoltcp::iface::{Config, Interface, PollIngressSingleResult, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const DNS_TCP_PORT: u16 = 53;
const DEFAULT_RX_QUEUE_PACKETS: usize = 128;
const DEFAULT_TX_QUEUE_PACKETS: usize = 128;
const DEFAULT_SOCKET_BUFFER_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_EVENT_COUNT: usize = 256;
const DEFAULT_MAX_EVENT_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_OUTBOUND_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_OUTBOUND_BYTES_PER_SESSION: usize = 128 * 1024;
const DEFAULT_IDLE_TIMEOUT_MS: i64 = 120_000;
const TCP_KEEP_ALIVE_MS: u64 = 30_000;
const MAX_DATA_EVENT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
}

impl FlowKey {
    fn public(self) -> TcpDnsFlow {
        TcpDnsFlow {
            client_ip: self.client_ip,
            client_port: self.client_port,
            server_ip: self.server_ip,
            server_port: self.server_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpDnsFlow {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpDnsEvent {
    SessionOpened { session_id: u64, flow: TcpDnsFlow },
    Data { session_id: u64, bytes: Vec<u8> },
    PeerHalfClosed { session_id: u64 },
    SessionClosed { session_id: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpDnsTransportError {
    InvalidConfiguration,
    SessionNotFound,
    InvalidDnsTcpFraming,
    ResponseLimitExceeded,
    Queue(TunQueueError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpDnsTransportStats {
    pub active_sessions: usize,
    pub queued_events: usize,
    pub queued_event_bytes: usize,
    pub queued_outbound_bytes: usize,
    pub sessions_rejected_at_capacity: u64,
    pub packets_rejected_by_tun_queue: u64,
    pub responses_rejected_by_limit: u64,
    pub idle_sessions_expired: u64,
}

struct Session {
    id: u64,
    handle: SocketHandle,
    flow: FlowKey,
    opened_event_sent: bool,
    peer_half_closed_event_sent: bool,
    closing: bool,
    last_activity_ms: i64,
    outbound: VecDeque<Vec<u8>>,
    outbound_head_offset: usize,
    outbound_bytes: usize,
}

pub struct TcpDnsTransport {
    iface: Interface,
    device: TunPacketDevice,
    sockets: SocketSet<'static>,
    sessions: HashMap<FlowKey, Session>,
    next_session_id: u64,
    events: VecDeque<TcpDnsEvent>,
    event_bytes: usize,
    max_sessions: usize,
    max_event_count: usize,
    max_event_bytes: usize,
    max_outbound_bytes: usize,
    max_outbound_bytes_per_session: usize,
    pending_outbound_bytes: usize,
    idle_timeout_ms: i64,
    sessions_rejected_at_capacity: u64,
    packets_rejected_by_tun_queue: u64,
    responses_rejected_by_limit: u64,
    idle_sessions_expired: u64,
}

impl TcpDnsTransport {
    /// Creates one smoltcp interface/socket-set owner for a single Android TUN.
    /// The default routes point back to the VPN client's assigned addresses.
    pub fn new(
        mtu: usize,
        tun_client_ipv4: Ipv4Address,
        tun_client_ipv6: Ipv6Address,
        max_sessions: usize,
    ) -> Result<Self, TcpDnsTransportError> {
        if mtu < 576 || max_sessions == 0 {
            return Err(TcpDnsTransportError::InvalidConfiguration);
        }

        let rx_bytes = mtu.saturating_mul(DEFAULT_RX_QUEUE_PACKETS);
        let tx_bytes = mtu.saturating_mul(DEFAULT_TX_QUEUE_PACKETS);
        let mut device = TunPacketDevice::new_with_byte_limits(
            mtu,
            DEFAULT_RX_QUEUE_PACKETS,
            DEFAULT_TX_QUEUE_PACKETS,
            rx_bytes,
            tx_bytes,
        );

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::ZERO);
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 1)), 32))
                .expect("smoltcp address capacity supports IPv4");
            addresses
                .push(IpCidr::new(
                    IpAddress::Ipv6(Ipv6Address::new(0xfd77, 0, 0, 0, 0, 0, 0, 1)),
                    128,
                ))
                .expect("smoltcp address capacity supports IPv6");
        });
        iface.set_any_ip(true);
        iface
            .routes_mut()
            .add_default_ipv4_route(tun_client_ipv4)
            .map_err(|_| TcpDnsTransportError::InvalidConfiguration)?;
        iface
            .routes_mut()
            .add_default_ipv6_route(tun_client_ipv6)
            .map_err(|_| TcpDnsTransportError::InvalidConfiguration)?;

        Ok(Self {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            sessions: HashMap::with_capacity(max_sessions),
            next_session_id: 1,
            events: VecDeque::with_capacity(DEFAULT_MAX_EVENT_COUNT),
            event_bytes: 0,
            max_sessions,
            max_event_count: DEFAULT_MAX_EVENT_COUNT,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            max_outbound_bytes: DEFAULT_MAX_OUTBOUND_BYTES,
            max_outbound_bytes_per_session: DEFAULT_MAX_OUTBOUND_BYTES_PER_SESSION,
            pending_outbound_bytes: 0,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            sessions_rejected_at_capacity: 0,
            packets_rejected_by_tun_queue: 0,
            responses_rejected_by_limit: 0,
            idle_sessions_expired: 0,
        })
    }

    /// Enqueues one complete IP packet from Android's TUN.
    /// Listener sockets are allocated before the next poll for new TCP/53 SYNs.
    /// Retransmitted SYNs reuse the existing flow entry.
    pub fn enqueue_packet(&mut self, packet: Vec<u8>, now: Instant) -> Result<(), TcpDnsTransportError> {
        let parsed_syn = parse_dns_tcp_syn(&packet);
        let parsed_flow = parse_dns_tcp_flow(&packet);

        if let Some(flow) = parsed_flow {
            if let Some(session) = self.sessions.get_mut(&flow) {
                session.last_activity_ms = now.total_millis();
            }
        }

        if let Err(error) = self.device.enqueue_rx(packet) {
            self.packets_rejected_by_tun_queue += 1;
            return Err(TcpDnsTransportError::Queue(error));
        }

        if let Some(flow) = parsed_syn {
            if !self.sessions.contains_key(&flow) {
                if self.sessions.len() >= self.max_sessions {
                    self.sessions_rejected_at_capacity += 1;
                } else {
                    self.create_listener(flow, now);
                }
            }
        }
        Ok(())
    }

    /// Advances the TCP state machine with a strict ingress packet budget.
    /// Call repeatedly while ingress remains queued; this avoids unbounded
    /// Interface::poll work on the production TUN owner thread.
    pub fn poll(&mut self, now: Instant, max_ingress_packets: usize) -> usize {
        let mut processed = 0usize;
        for _ in 0..max_ingress_packets {
            match self
                .iface
                .poll_ingress_single(now, &mut self.device, &mut self.sockets)
            {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed
                | PollIngressSingleResult::SocketStateChanged => processed += 1,
            }
        }

        self.expire_idle_sessions(now.total_millis());
        self.flush_outbound();
        self.iface.poll_maintenance(now);
        self.iface.poll_egress(now, &mut self.device, &mut self.sockets);
        self.collect_socket_events(now.total_millis());
        processed
    }

    /// Dequeues one IP packet generated by smoltcp for writing to the TUN.
    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.device.dequeue_tx()
    }

    /// Dequeues one ordered event for the Kotlin DNS/session owner.
    pub fn take_event(&mut self) -> Option<TcpDnsEvent> {
        let event = self.events.pop_front()?;
        if let TcpDnsEvent::Data { bytes, .. } = &event {
            self.event_bytes = self.event_bytes.saturating_sub(bytes.len());
        }
        Some(event)
    }

    /// Queues one or more complete RFC 1035 DNS/TCP frames for a live session.
    /// The TCP owner sends these bytes through smoltcp; this method performs no I/O.
    pub fn queue_response(
        &mut self,
        session_id: u64,
        framed_dns_bytes: Vec<u8>,
    ) -> Result<(), TcpDnsTransportError> {
        if !is_complete_dns_tcp_framing(&framed_dns_bytes) {
            return Err(TcpDnsTransportError::InvalidDnsTcpFraming);
        }

        let Some(session) = self.sessions.values_mut().find(|s| s.id == session_id) else {
            return Err(TcpDnsTransportError::SessionNotFound);
        };
        let next_session_bytes = session.outbound_bytes.saturating_add(framed_dns_bytes.len());
        let next_global_bytes = self.pending_outbound_bytes.saturating_add(framed_dns_bytes.len());
        if next_session_bytes > self.max_outbound_bytes_per_session
            || next_global_bytes > self.max_outbound_bytes
        {
            self.responses_rejected_by_limit += 1;
            return Err(TcpDnsTransportError::ResponseLimitExceeded);
        }

        session.outbound_bytes = next_session_bytes;
        session.outbound.push_back(framed_dns_bytes);
        self.pending_outbound_bytes = next_global_bytes;
        Ok(())
    }

    /// Closes a session. Graceful close should be requested only after all
    /// DNS responses have been queued and flushed; abort sends a TCP RST.
    pub fn close_session(&mut self, session_id: u64, abort: bool) -> bool {
        let Some(session) = self.sessions.values_mut().find(|s| s.id == session_id) else {
            return false;
        };
        if session.closing {
            return true;
        }
        if !abort && session.outbound_bytes > 0 {
            return false;
        }
        let socket = self.sockets.get_mut::<tcp::Socket>(session.handle);
        if abort {
            socket.abort();
        } else {
            socket.close();
        }
        session.closing = true;
        true
    }

    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    pub fn queued_rx_packets(&self) -> usize {
        self.device.queued_rx()
    }

    pub fn stats(&self) -> TcpDnsTransportStats {
        TcpDnsTransportStats {
            active_sessions: self.sessions.len(),
            queued_events: self.events.len(),
            queued_event_bytes: self.event_bytes,
            queued_outbound_bytes: self.pending_outbound_bytes,
            sessions_rejected_at_capacity: self.sessions_rejected_at_capacity,
            packets_rejected_by_tun_queue: self.packets_rejected_by_tun_queue,
            responses_rejected_by_limit: self.responses_rejected_by_limit,
            idle_sessions_expired: self.idle_sessions_expired,
        }
    }

    fn create_listener(&mut self, flow: FlowKey, now: Instant) {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; DEFAULT_SOCKET_BUFFER_BYTES]),
            tcp::SocketBuffer::new(vec![0; DEFAULT_SOCKET_BUFFER_BYTES]),
        );
        socket.set_keep_alive(Some(Duration::from_millis(TCP_KEEP_ALIVE_MS)));
        socket.set_timeout(Some(Duration::from_millis(self.idle_timeout_ms as u64)));

        let endpoint = IpListenEndpoint {
            addr: Some(to_smoltcp_ip(flow.server_ip)),
            port: flow.server_port,
        };
        if socket.listen(endpoint).is_err() {
            return;
        }

        let handle = self.sockets.add(socket);
        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        self.sessions.insert(
            flow,
            Session {
                id,
                handle,
                flow,
                opened_event_sent: false,
                peer_half_closed_event_sent: false,
                closing: false,
                last_activity_ms: now.total_millis(),
                outbound: VecDeque::new(),
                outbound_head_offset: 0,
                outbound_bytes: 0,
            },
        );
    }

    fn flush_outbound(&mut self) {
        let mut drained_total = 0usize;
        for session in self.sessions.values_mut() {
            if session.outbound.is_empty() {
                continue;
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(session.handle);
            while socket.can_send() {
                let Some(front) = session.outbound.front() else {
                    break;
                };
                let remaining = &front[session.outbound_head_offset..];
                if remaining.is_empty() {
                    session.outbound.pop_front();
                    session.outbound_head_offset = 0;
                    continue;
                }
                let accepted = match socket.send_slice(remaining) {
                    Ok(count) => count,
                    Err(_) => 0,
                };
                if accepted == 0 {
                    break;
                }
                session.outbound_head_offset += accepted;
                session.outbound_bytes = session.outbound_bytes.saturating_sub(accepted);
                drained_total += accepted;
                if session.outbound_head_offset == front.len() {
                    session.outbound.pop_front();
                    session.outbound_head_offset = 0;
                }
            }
        }
        self.pending_outbound_bytes = self.pending_outbound_bytes.saturating_sub(drained_total);
    }

    fn collect_socket_events(&mut self, now_ms: i64) {
        let mut pending = Vec::new();
        let mut pending_bytes = 0usize;
        let mut pending_count = self.events.len();
        let mut closed_flows = Vec::new();

        for (flow, session) in self.sessions.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(session.handle);
            let state = socket.state();

            if !session.opened_event_sent
                && state == tcp::State::Established
                && pending_count < self.max_event_count
            {
                pending.push(TcpDnsEvent::SessionOpened {
                    session_id: session.id,
                    flow: session.flow.public(),
                });
                pending_count += 1;
                session.opened_event_sent = true;
                session.last_activity_ms = now_ms;
            }

            if session.opened_event_sent
                && socket.can_recv()
                && pending_count < self.max_event_count
            {
                let event_capacity = self
                    .max_event_bytes
                    .saturating_sub(self.event_bytes.saturating_add(pending_bytes));
                let read_capacity = socket
                    .recv_queue()
                    .min(MAX_DATA_EVENT_BYTES)
                    .min(event_capacity);
                if read_capacity > 0 {
                    let mut bytes = vec![0u8; read_capacity];
                    if let Ok(read) = socket.recv_slice(&mut bytes) {
                        if read > 0 {
                            bytes.truncate(read);
                            pending_bytes += read;
                            pending_count += 1;
                            session.last_activity_ms = now_ms;
                            pending.push(TcpDnsEvent::Data {
                                session_id: session.id,
                                bytes,
                            });
                        }
                    }
                }
            }

            if state == tcp::State::CloseWait
                && !session.peer_half_closed_event_sent
                && pending_count < self.max_event_count
            {
                pending.push(TcpDnsEvent::PeerHalfClosed {
                    session_id: session.id,
                });
                pending_count += 1;
                session.peer_half_closed_event_sent = true;
            }

            if state == tcp::State::Closed && pending_count < self.max_event_count {
                pending.push(TcpDnsEvent::SessionClosed {
                    session_id: session.id,
                });
                pending_count += 1;
                closed_flows.push(*flow);
            }
        }

        for event in pending {
            if let TcpDnsEvent::Data { bytes, .. } = &event {
                self.event_bytes = self.event_bytes.saturating_add(bytes.len());
            }
            self.events.push_back(event);
        }

        for flow in closed_flows {
            if let Some(session) = self.sessions.remove(&flow) {
                self.pending_outbound_bytes = self
                    .pending_outbound_bytes
                    .saturating_sub(session.outbound_bytes);
                self.sockets.remove(session.handle);
            }
        }
    }

    fn expire_idle_sessions(&mut self, now_ms: i64) {
        for session in self.sessions.values_mut() {
            if session.closing || now_ms.saturating_sub(session.last_activity_ms) < self.idle_timeout_ms {
                continue;
            }
            self.sockets.get_mut::<tcp::Socket>(session.handle).abort();
            session.closing = true;
            self.idle_sessions_expired += 1;
        }
    }
}

fn parse_dns_tcp_flow(packet: &[u8]) -> Option<FlowKey> {
    let parsed = validate_tun_l4_packet(packet).ok()?;
    if !parsed.is_tcp() || parsed.destination_port != DNS_TCP_PORT {
        return None;
    }
    Some(FlowKey {
        client_ip: parsed.source,
        client_port: parsed.source_port,
        server_ip: parsed.destination,
        server_port: parsed.destination_port,
    })
}

fn parse_dns_tcp_syn(packet: &[u8]) -> Option<FlowKey> {
    let flow = parse_dns_tcp_flow(packet)?;
    let parsed = validate_tun_l4_packet(packet).ok()?;
    let flags_offset = parsed.transport_offset.checked_add(13)?;
    let flags = *packet.get(flags_offset)?;
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None;
    }
    Some(flow)
}

fn to_smoltcp_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            IpAddress::Ipv4(Ipv4Address::new(a, b, c, d))
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            let words = [
                u16::from_be_bytes([octets[0], octets[1]]),
                u16::from_be_bytes([octets[2], octets[3]]),
                u16::from_be_bytes([octets[4], octets[5]]),
                u16::from_be_bytes([octets[6], octets[7]]),
                u16::from_be_bytes([octets[8], octets[9]]),
                u16::from_be_bytes([octets[10], octets[11]]),
                u16::from_be_bytes([octets[12], octets[13]]),
                u16::from_be_bytes([octets[14], octets[15]]),
            ];
            IpAddress::Ipv6(Ipv6Address::new(
                words[0], words[1], words[2], words[3],
                words[4], words[5], words[6], words[7],
            ))
        }
    }
}

fn is_complete_dns_tcp_framing(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 2 {
            return false;
        }
        let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        if !(12..=u16::MAX as usize).contains(&length) {
            return false;
        }
        let Some(end) = offset.checked_add(2 + length) else {
            return false;
        };
        if end > bytes.len() {
            return false;
        }
        offset = end;
    }
    offset == bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_complete_dns_tcp_frames() {
        let frame = [0, 12, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(is_complete_dns_tcp_framing(&frame));
        assert!(!is_complete_dns_tcp_framing(&frame[..13]));
        assert!(!is_complete_dns_tcp_framing(&[0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!is_complete_dns_tcp_framing(&[]));
    }

    #[test]
    fn converts_ipv4_and_ipv6_addresses_for_smoltcp() {
        let v4 = to_smoltcp_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(v4, IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4)));
        let v6 = to_smoltcp_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(v6, IpAddress::Ipv6(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1)));
    }
}
