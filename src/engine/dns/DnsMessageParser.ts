export interface DnsQuestion {
  id: number;
  requestFlags: number;
  domain: string;
  type: number;
  dnsClass: number;
  /** Exact question bytes (QNAME, QTYPE, QCLASS), safe to copy into a reply. */
  wireQuestion: Uint8Array;
  ednsUdpPayloadSize: number | null;
  ednsDnssecOk: boolean;
}

export type DnsParseResult =
  | { valid: true; question: DnsQuestion }
  | { valid: false; reason: string };

const HEADER_SIZE = 12;
const MAX_MESSAGE_SIZE = 65_535;
const TYPE_OPT = 41;

function u16(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
}

/**
 * Strict parser for a single-question DNS query.
 * Accepts no answer/authority records and at most one EDNS(0) OPT record.
 */
export const DnsMessageParser = {
  parse(packet: Uint8Array): DnsParseResult {
    if (packet.length < HEADER_SIZE) return { valid: false, reason: 'dns_header_truncated' };
    if (packet.length > MAX_MESSAGE_SIZE) return { valid: false, reason: 'dns_message_too_large' };

    const id = u16(packet, 0);
    const flags = u16(packet, 2);
    const qdCount = u16(packet, 4);
    const anCount = u16(packet, 6);
    const nsCount = u16(packet, 8);
    const arCount = u16(packet, 10);

    if ((flags & 0x8000) !== 0) return { valid: false, reason: 'dns_response_not_query' };
    if (((flags >>> 11) & 0x0f) !== 0) return { valid: false, reason: 'dns_opcode_unsupported' };
    if ((flags & 0x0200) !== 0) return { valid: false, reason: 'dns_truncated_query' };
    if ((flags & 0x0040) !== 0) return { valid: false, reason: 'dns_reserved_flag_set' };
    if ((flags & 0x000f) !== 0) return { valid: false, reason: 'dns_query_rcode_nonzero' };
    if (qdCount !== 1) return { valid: false, reason: 'dns_question_count_unsupported' };
    if (anCount !== 0 || nsCount !== 0) return { valid: false, reason: 'dns_query_sections_unsupported' };
    if (arCount > 1) return { valid: false, reason: 'dns_additional_count_unsupported' };

    let offset = HEADER_SIZE;
    const questionStart = offset;
    const labels: string[] = [];
    let wireNameLength = 1;

    while (true) {
      if (offset >= packet.length) return { valid: false, reason: 'dns_qname_truncated' };
      const length = packet[offset++] & 0xff;
      if (length === 0) break;
      if ((length & 0xc0) !== 0) return { valid: false, reason: 'dns_qname_compression_unsupported' };
      if (length > 63) return { valid: false, reason: 'dns_label_too_long' };
      if (offset + length > packet.length) return { valid: false, reason: 'dns_label_truncated' };
      wireNameLength += length + 1;
      if (wireNameLength > 255) return { valid: false, reason: 'dns_qname_too_long' };

      const slice = packet.subarray(offset, offset + length);
      let label = '';
      for (let i = 0; i < slice.length; i++) {
        const b = slice[i] & 0xff;
        if (b < 0x21 || b > 0x7e || b === 0x2e) {
          return { valid: false, reason: 'dns_label_non_hostname_ascii' };
        }
        label += String.fromCharCode(b);
      }
      labels.push(label);
      offset += length;
    }

    if (labels.length === 0) return { valid: false, reason: 'dns_root_name_unsupported' };
    if (offset + 4 > packet.length) return { valid: false, reason: 'dns_question_truncated' };

    const type = u16(packet, offset);
    const dnsClass = u16(packet, offset + 2);
    offset += 4;
    const questionEnd = offset;

    let ednsUdpPayloadSize: number | null = null;
    let ednsDnssecOk = false;

    if (arCount === 1) {
      if (offset + 11 > packet.length) return { valid: false, reason: 'dns_opt_truncated' };
      if ((packet[offset++] & 0xff) !== 0) return { valid: false, reason: 'dns_opt_owner_unsupported' };
      if (u16(packet, offset) !== TYPE_OPT) return { valid: false, reason: 'dns_additional_record_unsupported' };
      offset += 2;
      ednsUdpPayloadSize = u16(packet, offset);
      offset += 2;
      ednsDnssecOk = (u16(packet, offset + 2) & 0x8000) !== 0;
      offset += 4;
      const rdLength = u16(packet, offset);
      offset += 2;
      const rdataEnd = offset + rdLength;
      if (rdataEnd !== packet.length) return { valid: false, reason: 'dns_opt_rdata_length_invalid' };
      while (offset < rdataEnd) {
        if (offset + 4 > rdataEnd) return { valid: false, reason: 'dns_opt_option_header_truncated' };
        const optionLength = u16(packet, offset + 2);
        offset += 4;
        if (offset + optionLength > rdataEnd) return { valid: false, reason: 'dns_opt_option_data_truncated' };
        offset += optionLength;
      }
    }

    if (offset !== packet.length) return { valid: false, reason: 'dns_trailing_bytes' };

    return {
      valid: true,
      question: {
        id,
        requestFlags: flags,
        domain: labels.join('.'),
        type,
        dnsClass,
        wireQuestion: packet.slice(questionStart, questionEnd),
        ednsUdpPayloadSize,
        ednsDnssecOk,
      },
    };
  },
};

export interface BuildDnsQueryOptions {
  id?: number;
  qtype?: number;
  qclass?: number;
  rd?: boolean;
  cd?: boolean;
  ednsPayloadSize?: number | null;
  dnssecOk?: boolean;
}

export function buildDnsQuery(domain: string, options: BuildDnsQueryOptions = {}): Uint8Array {
  const clean = domain.trim().replace(/\.$/, '');
  const labels = clean ? clean.split('.') : [];
  const qnameBytes: number[] = [];
  for (const label of labels) {
    const encoded = new TextEncoder().encode(label);
    qnameBytes.push(encoded.length & 0xff);
    for (const b of encoded) qnameBytes.push(b);
  }
  qnameBytes.push(0);

  const qtype = options.qtype ?? 1; // A
  const qclass = options.qclass ?? 1; // IN
  const id = (options.id ?? Math.floor(Math.random() * 0xffff)) & 0xffff;
  const rd = options.rd !== false;
  const cd = options.cd === true;
  const hasEdns = options.ednsPayloadSize !== null && options.ednsPayloadSize !== undefined;

  const optSize = hasEdns ? 11 : 0;
  const out = new Uint8Array(12 + qnameBytes.length + 4 + optSize);
  out[0] = (id >>> 8) & 0xff;
  out[1] = id & 0xff;
  const flags = (rd ? 0x0100 : 0) | (cd ? 0x0010 : 0);
  out[2] = (flags >>> 8) & 0xff;
  out[3] = flags & 0xff;
  out[4] = 0;
  out[5] = 1; // QDCOUNT = 1
  out[10] = 0;
  out[11] = hasEdns ? 1 : 0;

  let offset = 12;
  for (const b of qnameBytes) out[offset++] = b;
  out[offset++] = (qtype >>> 8) & 0xff;
  out[offset++] = qtype & 0xff;
  out[offset++] = (qclass >>> 8) & 0xff;
  out[offset++] = qclass & 0xff;

  if (hasEdns && options.ednsPayloadSize != null) {
    const payloadSize = options.ednsPayloadSize & 0xffff;
    out[offset++] = 0; // root owner
    out[offset++] = 0;
    out[offset++] = 41; // OPT
    out[offset++] = (payloadSize >>> 8) & 0xff;
    out[offset++] = payloadSize & 0xff;
    out[offset++] = 0; // ext rcode
    out[offset++] = 0; // edns version
    out[offset++] = options.dnssecOk ? 0x80 : 0;
    out[offset++] = 0;
    out[offset++] = 0; // rdlen = 0
    out[offset++] = 0;
  }

  return out;
}

export function buildPositiveDnsResponse(query: Uint8Array, ttlSeconds: number = 60): Uint8Array {
  const response = new Uint8Array(query.length + 16);
  response.set(query, 0);
  response[2] = 0x81;
  response[3] = 0x80;
  response[7] = 1; // ANCOUNT = 1
  const offset = query.length;
  response[offset] = 0xc0;
  response[offset + 1] = 0x0c; // pointer to QNAME
  response[offset + 3] = 1; // TYPE A
  response[offset + 5] = 1; // CLASS IN
  response[offset + 6] = (ttlSeconds >>> 24) & 0xff;
  response[offset + 7] = (ttlSeconds >>> 16) & 0xff;
  response[offset + 8] = (ttlSeconds >>> 8) & 0xff;
  response[offset + 9] = ttlSeconds & 0xff;
  response[offset + 11] = 4; // RDLENGTH
  response[offset + 12] = 192;
  response[offset + 13] = 0;
  response[offset + 14] = 2;
  response[offset + 15] = 1; // 192.0.2.1 (TEST-NET-1)
  return response;
}

export function formatPacketHex(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.subarray(i, Math.min(i + 16, bytes.length));
    const offsetStr = i.toString(16).padStart(4, '0');
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
    const ascii = Array.from(chunk)
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`${offsetStr}  ${hex.padEnd(47, ' ')}  ${ascii}`);
  }
  return lines.join('\n');
}

export function parseHexToBytes(hexInput: string): Uint8Array | null {
  const clean = hexInput.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length === 0 || clean.length % 2 !== 0) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export const DNS_QTYPE_NAMES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  65: 'HTTPS',
};
