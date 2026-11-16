const DNS_TYPE = new Map([[1, 'A'], [2, 'NS'], [5, 'CNAME'], [12, 'PTR'], [15, 'MX'], [16, 'TXT'], [28, 'AAAA'], [33, 'SRV'], [64, 'SVCB'], [65, 'HTTPS'], [255, 'ANY']]);
const HTTP_METHOD = /^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) [^\s]+ HTTP\/1\.[01]$/;
const DECODER = new TextDecoder('utf-8');
const U16 = (bytes, i) => bytes[i] * 256 + bytes[i + 1];
const U32 = (bytes, i) => U16(bytes, i) * 65536 + U16(bytes, i + 2);

function address4(bytes, offset) {
  return [...bytes.subarray(offset, offset + 4)].join('.');
}

function address6(bytes, offset) {
  const hextets = Array.from({ length: 8 }, (_, i) => U16(bytes, offset + i * 2).toString(16));
  const expanded = hextets.join(':');
  // URL supplies canonical IPv6 formatting without performing a request.
  try { return new URL(`http://[${expanded}]/`).hostname.slice(1, -1); }
  catch { return expanded; }
}

function network(bytes, link) {
  let offset = 0;
  let type;
  if (link === 1) {
    if (bytes.length < 14) return null;
    type = U16(bytes, 12);
    offset = 14;
    for (let count = 0; [0x8100, 0x88a8, 0x9100].includes(type) && count < 4; count++) {
      if (bytes.length < offset + 4) return null;
      type = U16(bytes, offset + 2);
      offset += 4;
    }
  } else if ([12, 101, 228, 229].includes(link)) {
    const version = bytes[0] >> 4;
    type = version === 4 ? 0x0800 : version === 6 ? 0x86dd : 0;
  } else if (link === 113 && bytes.length >= 16) {
    type = U16(bytes, 14);
    offset = 16;
  } else if (link === 276 && bytes.length >= 20) {
    type = U16(bytes, 0);
    offset = 20;
  } else return null;
  if (type === 0x0806) return { version: 0, label: 'ARP', start: offset, end: bytes.length };
  if (type === 0x0800 && bytes.length >= offset + 20 && (bytes[offset] >> 4) === 4) {
    const header = (bytes[offset] & 15) * 4;
    const length = U16(bytes, offset + 2);
    if (header < 20 || length < header || bytes.length < offset + header) return null;
    return {
      version: 4, source: address4(bytes, offset + 12), destination: address4(bytes, offset + 16),
      type: bytes[offset + 9], start: offset + header, end: Math.min(offset + length, bytes.length),
      fragmented: Boolean(U16(bytes, offset + 6) & 0x1fff),
    };
  }
  if (type === 0x86dd && bytes.length >= offset + 40 && (bytes[offset] >> 4) === 6) {
    const length = U16(bytes, offset + 4);
    const end = length ? Math.min(offset + 40 + length, bytes.length) : bytes.length;
    const source = address6(bytes, offset + 8);
    const destination = address6(bytes, offset + 24);
    let next = bytes[offset + 6];
    let start = offset + 40;
    let fragmented = false;
    for (let count = 0; [0, 43, 44, 51, 60].includes(next) && count < 8; count++) {
      if (start + 2 > end) return null;
      const size = next === 44 ? 8 : next === 51 ? (bytes[start + 1] + 2) * 4 : (bytes[start + 1] + 1) * 8;
      if (start + size > end) return null;
      if (next === 44) fragmented ||= Boolean(U16(bytes, start + 2) & 0xfff8);
      next = bytes[start];
      start += size;
      if (fragmented) break;
    }
    return { version: 6, source, destination, type: next, start, end, fragmented };
  }
  return null;
}

function dnsName(bytes, start) {
  const parts = [];
  const seen = new Set();
  let cursor = start;
  let end;
  for (let steps = 0; steps < 48 && cursor < bytes.length; steps++) {
    if (seen.has(cursor)) return null;
    seen.add(cursor);
    const size = bytes[cursor++];
    if (!size) {
      const name = parts.join('.') || '.';
      return name.length <= 253 ? { name, end: end ?? cursor } : null;
    }
    if ((size & 0xc0) === 0xc0) {
      if (cursor >= bytes.length) return null;
      end ??= cursor + 1;
      cursor = ((size & 0x3f) << 8) + bytes[cursor];
      continue;
    }
    if (size > 63 || cursor + size > bytes.length) return null;
    const token = DECODER.decode(bytes.subarray(cursor, cursor + size));
    if (!/^[a-z\d_-]+$/i.test(token)) return null;
    parts.push(token.toLowerCase());
    cursor += size;
  }
  return null;
}

function dns(payload, tcp) {
  let bytes = payload;
  if (tcp) {
    if (bytes.length < 2) return null;
    const length = U16(bytes, 0);
    if (bytes.length < length + 2) return null;
    bytes = bytes.subarray(2, length + 2);
  }
  if (bytes.length < 12 || U16(bytes, 4) < 1) return null;
  const first = dnsName(bytes, 12);
  if (!first || first.end + 4 > bytes.length) return null;
  const type = U16(bytes, first.end);
  const response = Boolean(bytes[2] & 0x80);
  return { kind: 'DNS', detail: `${response ? 'Response' : 'Query'} · ${first.name} · ${DNS_TYPE.get(type) ?? `type ${type}`}`, host: first.name };
}

function publicHost(value) {
  return /^(?:[a-z\d](?:[a-z\d.-]{0,251}[a-z\d.])?|\[[a-f\d.:-]+\])(?::\d{1,5})?$/i.test(value)
    ? value.toLowerCase() : null;
}

function http(payload) {
  const head = DECODER.decode(payload.subarray(0, 3072));
  const lineEnd = head.indexOf('\n');
  if (lineEnd < 0) return null;
  const first = head.slice(0, lineEnd).trimEnd();
  const request = HTTP_METHOD.exec(first);
  const response = /^HTTP\/1\.[01]\s([1-5]\d\d)(?:\s|$)/.exec(first);
  if (response) return { kind: 'HTTP', detail: `Response · ${response[1]}` };
  if (!request) return null;
  const headerEnd = head.search(/\r\n\r\n|\n\n/);
  const field = /^host:[ \t]*([^\r\n ]+)/im.exec(headerEnd < 0 ? head : head.slice(0, headerEnd));
  const host = field && publicHost(field[1]);
  return { kind: 'HTTP', detail: [`Request · ${request[1]}`, host].filter(Boolean).join(' · '), host };
}

function tls(bytes) {
  if (bytes.length < 9 || bytes[0] !== 22 || bytes[1] !== 3 || bytes[2] > 4) return null;
  const recordEnd = 5 + U16(bytes, 3);
  const handshakeEnd = 9 + bytes[6] * 65536 + bytes[7] * 256 + bytes[8];
  if (recordEnd > bytes.length || handshakeEnd > recordEnd) return null;
  if (bytes[5] === 2 && handshakeEnd >= 47) return { kind: 'TLS', detail: 'ServerHello observed' };
  if (bytes[5] !== 1 || handshakeEnd < 44) return null;
  let cursor = 43 + 1 + bytes[43];
  if (cursor + 2 > handshakeEnd) return null;
  cursor += 2 + U16(bytes, cursor);
  if (cursor + 1 > handshakeEnd) return null;
  cursor += 1 + bytes[cursor];
  if (cursor === handshakeEnd) return { kind: 'TLS', detail: 'ClientHello observed' };
  if (cursor + 2 > handshakeEnd) return null;
  const end = cursor + 2 + U16(bytes, cursor);
  if (end > handshakeEnd) return null;
  cursor += 2;
  let host;
  let ech = false;
  let modern = false;
  while (cursor + 4 <= end) {
    const type = U16(bytes, cursor);
    const length = U16(bytes, cursor + 2);
    const start = cursor + 4;
    const next = start + length;
    if (next > end) return null;
    if (type === 0 && length >= 5 && bytes[start + 2] === 0) {
      const size = U16(bytes, start + 3);
      if (size > 0 && size <= 253 && start + 5 + size <= next && size + 3 <= U16(bytes, start)) {
        host = publicHost(DECODER.decode(bytes.subarray(start + 5, start + 5 + size)));
      }
    }
    if (type === 43 && length >= 3) {
      for (let i = start + 1; i + 1 < next && i - start <= bytes[start]; i += 2) modern ||= U16(bytes, i) === 0x0304;
    }
    ech ||= type === 0xfe0d;
    cursor = next;
  }
  return { kind: 'TLS', detail: ['ClientHello', modern && 'TLS 1.3 offered', host, ech && 'ECH extension observed'].filter(Boolean).join(' · '), host };
}

export function decodeFrame(bytes, link) {
  const ip = network(bytes, link);
  if (!ip) return { protocol: 'Other', kind: 'Other', detail: 'Network header unavailable' };
  if (ip.label) return { protocol: ip.label, kind: ip.label, detail: 'Address Resolution Protocol' };
  const protocol = ({ 1: 'ICMP', 6: 'TCP', 17: 'UDP', 50: 'ESP', 58: 'ICMPv6' })[ip.type] ?? `IP ${ip.type}`;
  const base = { version: ip.version, source: ip.source, destination: ip.destination, protocol, kind: protocol };
  if (ip.fragmented) return { ...base, detail: 'Noninitial fragment' };
  const isTcp = protocol === 'TCP';
  if (!isTcp && protocol !== 'UDP') return base;
  const start = ip.start;
  if (ip.end < start + (isTcp ? 20 : 8)) return { ...base, detail: 'Transport header truncated' };
  const sourcePort = U16(bytes, start);
  const destinationPort = U16(bytes, start + 2);
  const headerLength = isTcp ? (bytes[start + 12] >> 4) * 4 : 8;
  const udpLength = isTcp ? Infinity : U16(bytes, start + 4);
  const end = !isTcp && udpLength ? Math.min(ip.end, start + udpLength) : ip.end;
  const transport = { ...base, sourcePort, destinationPort };
  if (isTcp) transport.tcp = { flags: bytes[start + 13], seq: U32(bytes, start + 4), ack: U32(bytes, start + 8) };
  if (headerLength < (isTcp ? 20 : 8) || start + headerLength > end) return { ...transport, detail: 'Transport payload truncated' };
  const payload = bytes.subarray(start + headerLength, end);
  let hint;
  if (sourcePort === 53 || destinationPort === 53) hint = dns(payload, isTcp);
  else if (isTcp && payload.length) hint = tls(payload) ?? http(payload);
  return { ...transport, ...(hint ?? {}) };
}
