//! JNI boundary for the smoltcp DNS/TCP transport.
//!
//! TUN reader threads call nativeEnqueuePacket, which only touches a bounded
//! ingress queue. A single Kotlin owner thread calls nativePoll, nativeTake*,
//! nativeQueueResponse and nativeCloseSession. The owner-thread check prevents
//! Interface/SocketSet from being accessed by multiple threads.

use crate::{TcpDnsEvent, TcpDnsTransport, TcpDnsTransportError};
use jni::objects::{JByteArray, JObject};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use smoltcp::time::Instant;
use smoltcp::wire::{Ipv4Address, Ipv6Address};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::ptr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::ThreadId;

const OK: jint = 1;
const REJECTED: jint = 0;
const INVALID_ARGUMENT: jint = -1;
const INVALID_HANDLE: jint = -2;
const WRONG_OWNER_THREAD: jint = -3;
const QUEUE_FULL: jint = -4;
const ERROR_SESSION_NOT_FOUND: jint = -5;
const ERROR_INVALID_FRAMING: jint = -6;
const ERROR_RESPONSE_LIMIT: jint = -7;
const MAX_INGRESS_PACKETS: usize = 128;
const MAX_INGRESS_BYTES: usize = 256 * 1024;

static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
static ENGINES: OnceLock<Mutex<HashMap<i64, Arc<NativeEngine>>>> = OnceLock::new();

struct IngressQueue {
    packets: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    mtu: usize,
    rejected: u64,
}

struct OwnerState {
    transport: TcpDnsTransport,
    owner_thread: Option<ThreadId>,
}

struct NativeEngine {
    ingress: Mutex<IngressQueue>,
    owner: Mutex<OwnerState>,
}

fn engines() -> &'static Mutex<HashMap<i64, Arc<NativeEngine>>> {
    ENGINES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn engine_for(handle: jlong) -> Option<Arc<NativeEngine>> {
    engines().lock().ok()?.get(&handle).cloned()
}

fn owner_for<'a>(
    engine: &'a NativeEngine,
) -> Result<MutexGuard<'a, OwnerState>, jint> {
    let mut owner = engine.owner.lock().map_err(|_| INVALID_HANDLE)?;
    let current = std::thread::current().id();
    match owner.owner_thread {
        Some(owner_thread) if owner_thread != current => Err(WRONG_OWNER_THREAD),
        Some(_) => Ok(owner),
        None => {
            owner.owner_thread = Some(current);
            Ok(owner)
        }
    }
}

fn empty_array(env: &mut JNIEnv<'_>) -> jbyteArray {
    env.new_byte_array(0)
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

fn array_from_bytes(env: &mut JNIEnv<'_>, bytes: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(bytes)
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

fn encode_ip(output: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(address) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            output.push(6);
            output.extend_from_slice(&address.octets());
        }
    }
}

fn encode_event(event: TcpDnsEvent) -> Vec<u8> {
    match event {
        TcpDnsEvent::SessionOpened { session_id, flow } => {
            let mut output = Vec::with_capacity(1 + 8 + 1 + 16 + 2 + 1 + 16 + 2);
            output.push(1);
            output.extend_from_slice(&session_id.to_be_bytes());
            encode_ip(&mut output, flow.client_ip);
            output.extend_from_slice(&flow.client_port.to_be_bytes());
            encode_ip(&mut output, flow.server_ip);
            output.extend_from_slice(&flow.server_port.to_be_bytes());
            output
        }
        TcpDnsEvent::Data { session_id, bytes } => {
            let mut output = Vec::with_capacity(1 + 8 + 4 + bytes.len());
            output.push(2);
            output.extend_from_slice(&session_id.to_be_bytes());
            output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            output.extend_from_slice(&bytes);
            output
        }
        TcpDnsEvent::PeerHalfClosed { session_id } => {
            let mut output = Vec::with_capacity(9);
            output.push(3);
            output.extend_from_slice(&session_id.to_be_bytes());
            output
        }
        TcpDnsEvent::SessionClosed { session_id } => {
            let mut output = Vec::with_capacity(9);
            output.push(4);
            output.extend_from_slice(&session_id.to_be_bytes());
            output
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_firewalldns_engine_android_NativeTcpDnsTransport_nativeCreate(
    mut env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    mtu: jint,
    tun_client_ipv4: JByteArray<'_>,
    tun_client_ipv6: JByteArray<'_>,
    max_sessions: jint,
) -> jlong {
    if mtu < 576 || max_sessions <= 0 {
        return 0;
    }
    let ipv4 = match env.convert_byte_array(&tun_client_ipv4) {
        Ok(bytes) if bytes.len() == 4 => Ipv4Address::new(bytes[0], bytes[1], bytes[2], bytes[3]),
        _ => return 0,
    };
    let ipv6 = match env.convert_byte_array(&tun_client_ipv6) {
        Ok(bytes) if bytes.len() == 16 => {
            let words = [
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
                u16::from_be_bytes([bytes[6], bytes[7]]),
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
            ];
            Ipv6Address::new(
                words[0], words[1], words[2], words[3],
                words[4], words[5], words[6], words[7],
            )
        }
        _ => return 0,
    };
    let transport = match TcpDnsTransport::new(mtu as usize, ipv4, ipv6, max_sessions as usize) {
        Ok(transport) => transport,
        Err(_) => return 0,
    };

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if handle <= 0 {
        return 0;
    }
    let engine = Arc::new(NativeEngine {
        ingress: Mutex::new(IngressQueue {
            packets: VecDeque::with_capacity(MAX_INGRESS_PACKETS),
            queued_bytes: 0,
            mtu: mtu as usize,
            rejected: 0,
        }),
        owner: Mutex::new(OwnerState {
            transport,
            owner_thread: None,
        }),
    });
    match engines().lock() {
        Ok(mut engines) => {
            engines.insert(handle, engine);
            handle
        }
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_firewalldns_engine_android_NativeTcpDnsTransport_nativeEnqueuePacket(
    mut env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    handle: jlong,
    packet: JByteArray<'_>,
    length: jint,
) -> jint {
    if length <= 0 {
        return INVALID_ARGUMENT;
    }
    let Some(engine) = engine_for(handle) else {
        return INVALID_HANDLE;
    };
    let bytes = match env.convert_byte_array(&packet) {
        Ok(bytes) if length as usize <= bytes.len() => bytes[..length as usize].to_vec(),
        _ => return INVALID_ARGUMENT,
    };
    let Ok(mut ingress) = engine.ingress.lock() else {
        return INVALID_HANDLE;
    };
    if bytes.is_empty() || bytes.len() > ingress.mtu {
        ingress.rejected += 1;
        return INVALID_ARGUMENT;
    }
    let next_bytes = ingress.queued_bytes.saturating_add(bytes.len());
    if ingress.packets.len() >= MAX_INGRESS_PACKETS || next_bytes > MAX_INGRESS_BYTES {
        ingress.rejected += 1;
        return QUEUE_FULL;
    }
    ingress.queued_bytes = next_bytes;
    ingress.packets.push_back(bytes);
    OK
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_firewalldns_engine_android_NativeTcpDnsTransport_nativePoll(
    _env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    handle: jlong,
    now_millis: jlong,
    max_ingress_packets: jint,
) -> jint {
    let Some(engine) = engine_for(handle) else {
        return INVALID_HANDLE;
    };
    let Ok(mut owner) = owner_for(&engine) else {
        return WRONG_OWNER_THREAD;
    };
    let budget = max_ingress_packets.clamp(0, 64) as usize;
    let packets = {
        let Ok(mut ingress) = engine.ingress.lock() else {
            return INVALID_HANDLE;
        };
        let mut packets = Vec::with_capacity(budget.min(ingress.packets.len()));
        for _ in 0..budget {
            let Some(packet) = ingress.packets.pop_front() else {
                break;
            };
            ingress.queued_bytes = ingress.queued_bytes.saturating_sub(packet.len());
            packets.push(packet);
        }
        packets
    };
    let now = Instant::from_millis(now_millis);
    for packet in packets {
        let _ = owner.transport.enqueue_packet(packet, now);
    }
    owner.transport.poll(now, budget) as jint
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_firewalldns_engine_android_NativeTcpDnsTransport_nativeTakePacket(
    mut env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    handle: jlong,
) -> jbyteArray {
    let Some(engine) = engine_for(handle) else {
        return empty_array(&mut env);
    };
    let Ok(mut owner) = owner_for(&engine) else {
        return empty_array(&mut env);
    };
    match owner.transport.take_packet() {
        Some(packet) => array_from_bytes(&mut env, &packet),
        None => empty_array(&mut env),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_firewalldns_engine_android_NativeTcpDnsTransport_nativeTakeEvent(
    mut env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    handle: jlong,
) -> jbyteArray {
    let Some(engine) = engine_for(handle) else {
        return empty_array(&mut env);
    };
    let Ok(mut owner) = owner_for(&engine) else {
        return empty_array(&mut env);
    };
    match owner.transport.take_event() {
        Some(event) => {
            let bytes = encode_event(event);
            array_from_bytes(&mut env, &bytes)
        }
        None => empty_array(&mut env),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_firewalldns_engine_android_NativeTcpDnsTransport_nativeQueueResponse(
    mut env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    handle: jlong,
    session_id: jlong,
    response: JByteArray<'_>,
) -> jint {
    let Some(engine) = engine_for(handle) else {
        return INVALID_HANDLE;
    };
    let Ok(mut owner) = owner_for(&engine) else {
        return WRONG_OWNER_THREAD;
    };
    let bytes = match env.convert_byte_array(&response) {
        Ok(bytes) => bytes,
        Err(_) => return INVALID_ARGUMENT,
    };
    match owner.transport.queue_response(session_id as u64, bytes) {
        Ok(()) => OK,
        Err(TcpDnsTransportError::SessionNotFound) => ERROR_SESSION_NOT_FOUND,
        Err(TcpDnsTransportError::InvalidDnsTcpFraming) => ERROR_INVALID_FRAMING,
        Err(TcpDnsTransportError::ResponseLimitExceeded) => ERROR_RESPONSE_LIMIT,
        Err(_) => INVALID_ARGUMENT,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_firewalldns_engine_android_NativeTcpDnsTransport_nativeCloseSession(
    _env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    handle: jlong,
    session_id: jlong,
    abort: jint,
) -> jint {
    let Some(engine) = engine_for(handle) else {
        return INVALID_HANDLE;
    };
    let Ok(mut owner) = owner_for(&engine) else {
        return WRONG_OWNER_THREAD;
    };
    if owner.transport.close_session(session_id as u64, abort != 0) {
        OK
    } else {
        REJECTED
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_firewalldns_engine_android_NativeTcpDnsTransport_nativeDestroy(
    _env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    handle: jlong,
) {
    if let Ok(mut engines) = engines().lock() {
        engines.remove(&handle);
    }
}
