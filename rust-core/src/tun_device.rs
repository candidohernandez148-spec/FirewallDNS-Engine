//! Bounded packet device for the FirewallDNS TUN-to-smoltcp boundary.
//!
//! This module deliberately does not own an Android file descriptor, perform
//! socket I/O, or forward traffic. The Android adapter remains responsible for
//! reading/writing the TUN descriptor and feeding packets into this device.
//! Keeping the queues bounded prevents an overloaded stack from consuming
//! unbounded memory.

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunQueueError {
    EmptyPacket,
    PacketExceedsMtu,
    ReceiveQueueFull,
}

pub struct TunPacketDevice {
    mtu: usize,
    rx_capacity: usize,
    tx_capacity: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    rx_rejected: u64,
    tx_rejected: u64,
}

impl TunPacketDevice {
    pub fn new(mtu: usize, rx_capacity: usize, tx_capacity: usize) -> Self {
        assert!(mtu > 0, "MTU must be positive");
        assert!(rx_capacity > 0, "RX capacity must be positive");
        assert!(tx_capacity > 0, "TX capacity must be positive");
        Self {
            mtu,
            rx_capacity,
            tx_capacity,
            rx_queue: VecDeque::with_capacity(rx_capacity),
            tx_queue: VecDeque::with_capacity(tx_capacity),
            rx_rejected: 0,
            tx_rejected: 0,
        }
    }

    /// Enqueue one complete IP packet read from Android's TUN descriptor.
    /// The caller retains ownership of the packet if this method rejects it.
    pub fn enqueue_rx(&mut self, packet: Vec<u8>) -> Result<(), TunQueueError> {
        if packet.is_empty() {
            self.rx_rejected += 1;
            return Err(TunQueueError::EmptyPacket);
        }
        if packet.len() > self.mtu {
            self.rx_rejected += 1;
            return Err(TunQueueError::PacketExceedsMtu);
        }
        if self.rx_queue.len() >= self.rx_capacity {
            self.rx_rejected += 1;
            return Err(TunQueueError::ReceiveQueueFull);
        }
        self.rx_queue.push_back(packet);
        Ok(())
    }

    /// Take the next complete IP packet produced by smoltcp for Android TUN.
    pub fn dequeue_tx(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    pub fn queued_rx(&self) -> usize { self.rx_queue.len() }
    pub fn queued_tx(&self) -> usize { self.tx_queue.len() }
    pub fn rx_rejected(&self) -> u64 { self.rx_rejected }
    pub fn tx_rejected(&self) -> u64 { self.tx_rejected }
    pub fn mtu(&self) -> usize { self.mtu }
}

pub struct TunRxToken(Vec<u8>);

impl RxToken for TunRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

pub struct TunTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    capacity: usize,
    mtu: usize,
    rejected: &'a mut u64,
}

impl TxToken for TunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if len == 0 || len > self.mtu || self.queue.len() >= self.capacity {
            *self.rejected += 1;
        } else {
            self.queue.push_back(packet);
        }
        result
    }
}

impl Device for TunPacketDevice {
    type RxToken<'a> = TunRxToken where Self: 'a;
    type TxToken<'a> = TunTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            TunRxToken(packet),
            TunTxToken {
                queue: &mut self.tx_queue,
                capacity: self.tx_capacity,
                mtu: self.mtu,
                rejected: &mut self.tx_rejected,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            queue: &mut self.tx_queue,
            capacity: self.tx_capacity,
            mtu: self.mtu,
            rejected: &mut self.tx_rejected,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_queue_is_bounded_and_rejects_invalid_packets() {
        let mut device = TunPacketDevice::new(1500, 1, 1);
        assert_eq!(device.enqueue_rx(Vec::new()), Err(TunQueueError::EmptyPacket));
        assert_eq!(device.enqueue_rx(vec![0; 1501]), Err(TunQueueError::PacketExceedsMtu));
        assert_eq!(device.enqueue_rx(vec![0x45; 20]), Ok(()));
        assert_eq!(device.enqueue_rx(vec![0x45; 20]), Err(TunQueueError::ReceiveQueueFull));
        assert_eq!(device.queued_rx(), 1);
        assert_eq!(device.rx_rejected(), 3);
    }

    #[test]
    fn smoltcp_receive_token_delivers_packet_and_tx_token_is_bounded() {
        let mut device = TunPacketDevice::new(1500, 4, 1);
        device.enqueue_rx(vec![0x45; 20]).unwrap();

        let (rx, tx) = device.receive(Instant::from_millis(0)).unwrap();
        let received_len = rx.consume(|packet| {
            assert_eq!(packet[0], 0x45);
            packet.len()
        });
        assert_eq!(received_len, 20);

        tx.consume(24, |packet| packet.fill(0x60));
        assert_eq!(device.queued_tx(), 1);

        device.transmit(Instant::from_millis(1)).unwrap()
            .consume(24, |packet| packet.fill(0x61));
        assert_eq!(device.queued_tx(), 1);
        assert_eq!(device.tx_rejected(), 1);

        let outgoing = device.dequeue_tx().unwrap();
        assert_eq!(outgoing.len(), 24);
        assert!(outgoing.iter().all(|byte| *byte == 0x60));
    }

    #[test]
    fn transmit_rejects_packets_larger_than_mtu() {
        let mut device = TunPacketDevice::new(64, 2, 2);
        device.transmit(Instant::from_millis(0)).unwrap()
            .consume(65, |packet| packet.fill(0xaa));
        assert_eq!(device.queued_tx(), 0);
        assert_eq!(device.tx_rejected(), 1);
    }

    #[test]
    fn advertises_ip_medium_and_configured_mtu() {
        let device = TunPacketDevice::new(1420, 2, 2);
        let caps = device.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 1420);
    }
}
