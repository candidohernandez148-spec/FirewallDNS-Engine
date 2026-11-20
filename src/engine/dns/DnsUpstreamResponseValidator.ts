const HEADER_SIZE = 12;
const RR_FIXED_SIZE = 10;
const MAX_MESSAGE_SIZE = 65_535;
const MAX_RECORDS = 4_096;
const MAX_NAME_STEPS = 256;
const MAX_NAME_LENGTH = 255;
const MAX_LABEL_LENGTH = 63;
const TYPE_OPT = 41;

function u16(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
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
  let expandedLength = 0;
  let steps = 0;

  while (steps++ < MAX_NAME_STEPS) {
    if (cursor < 0 || cursor >= message.length) return null;
    const length = message[cursor] & 0xff;
    if (length === 0) {
      expandedLength++;
      if (expandedLength > MAX_NAME_LENGTH) return null;
      return jumped ? consumed : cursor + 1;
    } else if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= message.length) return null;
      const pointer = ((length & 0x3f) << 8) | (message[cursor + 1] & 0xff);
      if (pointer >= cursor || pointer >= message.length) return null;
      if (!jumped) consumed = cursor + 2;
      jumped = true;
      cursor = pointer;
    } else if ((length & 0xc0) !== 0 || length > MAX_LABEL_LENGTH) {
      return null;
    } else {
      if (cursor + 1 + length > message.length) return null;
      expandedLength += length + 1;
      if (expandedLength > MAX_NAME_LENGTH) return null;
      cursor += length + 1;
    }
  }
  return null;
}

/**
 * Structural validation for an upstream DNS response.
 */
export const DnsUpstreamResponseValidator = {
  validate(message: Uint8Array, expectedQuestion: Uint8Array): string | null {
    if (message.length < HEADER_SIZE) return 'dns_upstream_response_header_truncated';
    if (message.length > MAX_MESSAGE_SIZE) return 'dns_upstream_response_too_large';
    if (u16(message, 4) !== 1) return 'dns_upstream_question_count_unsupported';

    const questionEnd = skipName(message, HEADER_SIZE);
    if (questionEnd === null) return 'dns_upstream_question_malformed';
    if (questionEnd + 4 > message.length) return 'dns_upstream_response_question_truncated';

    const actualQuestion = message.subarray(HEADER_SIZE, questionEnd + 4);
    if (!bytesEqual(actualQuestion, expectedQuestion)) return 'dns_upstream_question_mismatch';

    const answerCount = u16(message, 6);
    const authorityCount = u16(message, 8);
    const additionalCount = u16(message, 10);
    const totalRecords = answerCount + authorityCount + additionalCount;
    if (totalRecords > MAX_RECORDS) return 'dns_upstream_record_count_unsupported';

    let offset = questionEnd + 4;
    let optCount = 0;

    for (let index = 0; index < totalRecords; index++) {
      const ownerEnd = skipName(message, offset);
      if (ownerEnd === null) return 'dns_upstream_record_name_malformed';
      if (ownerEnd + RR_FIXED_SIZE > message.length) return 'dns_upstream_record_header_truncated';
      const type = u16(message, ownerEnd);
      const dataLength = u16(message, ownerEnd + 8);
      const dataStart = ownerEnd + RR_FIXED_SIZE;
      const dataEnd = dataStart + dataLength;
      if (dataEnd < dataStart || dataEnd > message.length) return 'dns_upstream_record_data_truncated';

      if (type === TYPE_OPT) {
        optCount++;
        if (index < answerCount + authorityCount || optCount > 1) {
          return 'dns_upstream_edns_record_position_invalid';
        }
        if (ownerEnd !== offset + 1 || (message[offset] & 0xff) !== 0) {
          return 'dns_upstream_edns_owner_invalid';
        }
        let optionOffset = dataStart;
        while (optionOffset < dataEnd) {
          if (optionOffset + 4 > dataEnd) return 'dns_upstream_edns_option_header_truncated';
          const optionLength = u16(message, optionOffset + 2);
          optionOffset += 4;
          if (optionOffset + optionLength > dataEnd) {
            return 'dns_upstream_edns_option_data_truncated';
          }
          optionOffset += optionLength;
        }
      }
      offset = dataEnd;
    }

    if (offset !== message.length) return 'dns_upstream_response_trailing_bytes';
    return null;
  },
};
