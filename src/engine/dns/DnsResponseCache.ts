import { DnsMessageParser } from './DnsMessageParser';
import { DnsUpstreamResponseValidator } from './DnsUpstreamResponseValidator';

export type DnsUpstreamTransport = 'UDP' | 'TCP' | 'DOH' | 'CACHE';

export interface DnsUpstreamResponse {
  message: Uint8Array;
  transport: DnsUpstreamTransport;
}

interface CacheEntry {
  response: Uint8Array;
  insertedAtMs: number;
  ttlMs: number;
}

const DEFAULT_MAX_ENTRIES = 2_048;
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_TTL_SECONDS = 86_400;
const DNS_HEADER_SIZE = 12;
const RR_FIXED_SIZE = 10;
const MAX_DNS_MESSAGE_SIZE = 65_535;
const MAX_RECORDS = 4_096;
const MAX_NAME_STEPS = 256;
const RD_MASK = 0x0100;
const QR_MASK = 0x8000;
const OPCODE_MASK = 0x7800;
const TC_MASK = 0x0200;
const RCODE_MASK = 0x000f;
const RCODE_NOERROR = 0;
const RCODE_NXDOMAIN = 3;
const TYPE_SOA = 6;
const TYPE_OPT = 41;

function u16(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
}

function u32(bytes: Uint8Array, offset: number): number {
  return (
    (((bytes[offset] & 0xff) << 24) >>> 0) +
    ((bytes[offset + 1] & 0xff) << 16) +
    ((bytes[offset + 2] & 0xff) << 8) +
    (bytes[offset + 3] & 0xff)
  );
}

function putU16(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >>> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
}

function putU32(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >>> 24) & 0xff;
  bytes[offset + 1] = (value >>> 16) & 0xff;
  bytes[offset + 2] = (value >>> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function skipName(message: Uint8Array, start: number): number | null {
  if (start < 0 || start >= message.length) return null;
  let cursor = start;
  let jumped = false;
  let consumed = -1;
  let steps = 0;
  while (steps++ < MAX_NAME_STEPS) {
    if (cursor < 0 || cursor >= message.length) return null;
    const length = message[cursor] & 0xff;
    if (length === 0) {
      return jumped ? consumed : cursor + 1;
    } else if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= message.length) return null;
      const pointer = ((length & 0x3f) << 8) | (message[cursor + 1] & 0xff);
      if (pointer >= message.length) return null;
      if (!jumped) consumed = cursor + 2;
      jumped = true;
      cursor = pointer;
    } else if ((length & 0xc0) !== 0 || length > 63) {
      return null;
    } else {
      if (cursor + 1 + length > message.length) return null;
      cursor += length + 1;
    }
  }
  return null;
}

function soaMinimum(message: Uint8Array, start: number, end: number): number | null {
  const firstNameEnd = skipName(message, start);
  if (firstNameEnd === null || firstNameEnd > end) return null;
  const secondNameEnd = skipName(message, firstNameEnd);
  if (secondNameEnd === null || secondNameEnd + 20 !== end) return null;
  return u32(message, secondNameEnd + 16);
}

function responseTtlSeconds(message: Uint8Array, expectedQuestion: Uint8Array): number | null {
  if (message.length < DNS_HEADER_SIZE || message.length > MAX_DNS_MESSAGE_SIZE) return null;
  const flags = u16(message, 2);
  if ((flags & QR_MASK) === 0 || (flags & TC_MASK) !== 0) return null;
  const rcode = flags & RCODE_MASK;
  if (rcode !== RCODE_NOERROR && rcode !== RCODE_NXDOMAIN) return null;
  if (u16(message, 4) !== 1) return null;

  const questionNameEnd = skipName(message, DNS_HEADER_SIZE);
  if (questionNameEnd === null || questionNameEnd + 4 > message.length) return null;
  const questionEnd = questionNameEnd + 4;
  if (!bytesEqual(message.subarray(DNS_HEADER_SIZE, questionEnd), expectedQuestion)) return null;

  let offset = questionEnd;
  const answerCount = u16(message, 6);
  const authorityCount = u16(message, 8);
  const additionalCount = u16(message, 10);
  const totalRecords = answerCount + authorityCount + additionalCount;
  if (totalRecords > MAX_RECORDS) return null;

  let positiveTtl: number | null = null;
  let negativeTtl: number | null = null;

  for (let index = 0; index < totalRecords; index++) {
    const section = index < answerCount ? 0 : index < answerCount + authorityCount ? 1 : 2;
    const nameEnd = skipName(message, offset);
    if (nameEnd === null || nameEnd + RR_FIXED_SIZE > message.length) return null;
    const type = u16(message, nameEnd);
    const ttl = u32(message, nameEnd + 4);
    const rdLength = u16(message, nameEnd + 8);
    const rdataStart = nameEnd + RR_FIXED_SIZE;
    const rdataEnd = rdataStart + rdLength;
    if (rdataEnd < rdataStart || rdataEnd > message.length) return null;

    if (section === 0 && type !== TYPE_OPT) {
      positiveTtl = positiveTtl === null ? ttl : Math.min(positiveTtl, ttl);
    } else if (section === 1 && type === TYPE_SOA) {
      const minimum = soaMinimum(message, rdataStart, rdataEnd);
      if (minimum === null) return null;
      const candidate = Math.min(ttl, minimum);
      negativeTtl = negativeTtl === null ? candidate : Math.min(negativeTtl, candidate);
    }
    offset = rdataEnd;
  }

  if (offset !== message.length) return null;
  let selected: number | null = null;
  if (rcode === RCODE_NXDOMAIN && negativeTtl !== null && positiveTtl !== null) {
    selected = Math.min(negativeTtl, positiveTtl);
  } else if (rcode === RCODE_NXDOMAIN) {
    selected = negativeTtl;
  } else if (answerCount === 0) {
    selected = negativeTtl;
  } else {
    selected = positiveTtl;
  }
  return selected !== null && selected > 0 ? selected : null;
}

function rewriteRemainingTtls(message: Uint8Array, remainingSeconds: number): boolean {
  if (message.length < DNS_HEADER_SIZE) return false;
  let offset = skipName(message, DNS_HEADER_SIZE);
  if (offset === null || offset + 4 > message.length) return false;
  offset += 4;
  const total = u16(message, 6) + u16(message, 8) + u16(message, 10);
  if (total > MAX_RECORDS) return false;

  for (let i = 0; i < total; i++) {
    const nameEnd = skipName(message, offset);
    if (nameEnd === null || nameEnd + RR_FIXED_SIZE > message.length) return false;
    const type = u16(message, nameEnd);
    const rdataLength = u16(message, nameEnd + 8);
    const rdataStart = nameEnd + RR_FIXED_SIZE;
    const rdataEnd = rdataStart + rdataLength;
    if (rdataEnd < rdataStart || rdataEnd > message.length) return false;
    if (type !== TYPE_OPT) {
      putU32(message, nameEnd + 4, Math.min(u32(message, nameEnd + 4), remainingSeconds));
    }
    offset = rdataEnd;
  }
  return offset === message.length;
}

/**
 * Bounded in-memory cache for validated upstream DNS messages.
 */
export class DnsResponseCache {
  private readonly maxEntries: number;
  private readonly maxBytes: number;
  private readonly maxTtlSeconds: number;
  private readonly entries = new Map<string, CacheEntry>();
  private currentBytes = 0;

  constructor(
    maxEntries: number = DEFAULT_MAX_ENTRIES,
    maxBytes: number = DEFAULT_MAX_BYTES,
    maxTtlSeconds: number = DEFAULT_MAX_TTL_SECONDS,
  ) {
    this.maxEntries = maxEntries;
    this.maxBytes = maxBytes;
    this.maxTtlSeconds = maxTtlSeconds;
  }

  get(upstream: string, query: Uint8Array, nowMs: number): DnsUpstreamResponse | null {
    const parsed = DnsMessageParser.parse(query);
    if (!parsed.valid) return null;

    const k = this.buildKey(upstream, query);
    const entry = this.entries.get(k);
    if (!entry) return null;

    const elapsedMs = nowMs - entry.insertedAtMs;
    if (elapsedMs < 0 || elapsedMs >= entry.ttlMs) {
      this.entries.delete(k);
      this.currentBytes -= entry.response.length;
      return null;
    }

    const remainingMs = entry.ttlMs - elapsedMs;
    const remainingSeconds = Math.max(1, Math.ceil(remainingMs / 1000));
    const response = entry.response.slice();
    putU16(response, 0, parsed.question.id);
    const flags = u16(response, 2);
    putU16(response, 2, (flags & ~RD_MASK) | (parsed.question.requestFlags & RD_MASK));
    response.set(parsed.question.wireQuestion, DNS_HEADER_SIZE);
    if (!rewriteRemainingTtls(response, remainingSeconds)) return null;

    return { message: response, transport: 'CACHE' };
  }

  put(upstream: string, query: Uint8Array, response: Uint8Array, nowMs: number): boolean {
    const parsed = DnsMessageParser.parse(query);
    if (!parsed.valid) return false;
    if (response.length < DNS_HEADER_SIZE || u16(response, 0) !== parsed.question.id) return false;
    if ((u16(response, 2) & OPCODE_MASK) !== (parsed.question.requestFlags & OPCODE_MASK)) return false;
    if (DnsUpstreamResponseValidator.validate(response, parsed.question.wireQuestion) !== null) {
      return false;
    }
    const ttlSeconds = responseTtlSeconds(response, parsed.question.wireQuestion);
    if (ttlSeconds === null || ttlSeconds <= 0) return false;

    const boundedTtl = Math.min(ttlSeconds, this.maxTtlSeconds);
    const ttlMs = boundedTtl * 1000;
    const stored = response.slice();
    if (stored.length > this.maxBytes) return false;

    const k = this.buildKey(upstream, query);
    const existing = this.entries.get(k);
    if (existing) {
      this.currentBytes -= existing.response.length;
      this.entries.delete(k);
    }

    // Evict expired first
    for (const [entryKey, entry] of this.entries.entries()) {
      const elapsed = nowMs - entry.insertedAtMs;
      if (elapsed < 0 || elapsed >= entry.ttlMs) {
        this.entries.delete(entryKey);
        this.currentBytes -= entry.response.length;
      }
    }

    while (
      this.entries.size > 0 &&
      (this.entries.size >= this.maxEntries || this.currentBytes + stored.length > this.maxBytes)
    ) {
      const victimKey = this.entries.keys().next().value;
      if (victimKey === undefined) break;
      const victim = this.entries.get(victimKey);
      if (victim) {
        this.currentBytes -= victim.response.length;
        this.entries.delete(victimKey);
      }
    }

    this.entries.set(k, { response: stored, insertedAtMs: nowMs, ttlMs });
    this.currentBytes += stored.length;
    return true;
  }

  clear(): void {
    this.entries.clear();
    this.currentBytes = 0;
  }

  get size(): number {
    return this.entries.size;
  }

  get bytes(): number {
    return this.currentBytes;
  }

  private buildKey(upstream: string, query: Uint8Array): string {
    const canonical = query.slice();
    canonical[0] = 0;
    canonical[1] = 0;
    putU16(canonical, 2, u16(canonical, 2) & ~RD_MASK);
    let hex = '';
    for (let i = 0; i < canonical.length; i++) {
      hex += canonical[i].toString(16).padStart(2, '0');
    }
    return `${upstream}|${hex}`;
  }
}
