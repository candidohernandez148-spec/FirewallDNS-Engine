/**
 * Canonicalizes DNS names, including service labels such as _sip._tcp and IDN labels.
 */
export const DomainNormalizer = {
  normalize(hostname: string): string | null {
    const trimmed = hostname.trim();
    const input = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
    if (input.length === 0 || input.length > 253 || /\s/.test(input)) {
      return null;
    }

    const labels = input.split('.');
    if (labels.some((label) => label.length === 0 || label.length > 63)) {
      return null;
    }

    const asciiLabels: string[] = [];
    for (const label of labels) {
      const lower = label.toLowerCase();
      if (lower.includes('_')) {
        if (!/^[a-z0-9_-]+$/.test(lower)) {
          return null;
        }
        asciiLabels.push(lower);
      } else if (/^[\x20-\x7e]+$/.test(label)) {
        if (!/^[a-z0-9-]+$/.test(lower)) {
          return null;
        }
        asciiLabels.push(lower);
      } else {
        // IDN / Unicode label -> Punycode via standard URL WHATWG IDNA processing
        try {
          const parsed = new URL(`http://${label}.invalid`);
          const converted = parsed.hostname.replace(/\.invalid$/, '').toLowerCase();
          if (!converted || converted.includes('.') || !/^[a-z0-9-]+$/.test(converted)) {
            return null;
          }
          asciiLabels.push(converted);
        } catch {
          return null;
        }
      }
    }

    for (const label of asciiLabels) {
      if (
        label.length === 0 ||
        label.length > 63 ||
        label.startsWith('-') ||
        label.endsWith('-') ||
        !/^[a-z0-9_-]+$/.test(label)
      ) {
        return null;
      }
    }

    const joined = asciiLabels.join('.');
    return joined.length <= 253 ? joined : null;
  },
};
