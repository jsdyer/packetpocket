export function endpoint(address, port) {
  if (!address) return 'Unavailable';
  if (port === undefined) return address;
  return address.includes(':') ? `[${address}]:${port}` : `${address}:${port}`;
}

export function flowKey(packet) {
  if (!packet.source || !packet.destination) return null;
  return [endpoint(packet.source, packet.sourcePort), endpoint(packet.destination, packet.destinationPort)].sort().join(' ↔ ') + ` · ${packet.protocol}`;
}

export function captureSummary(packets) {
  const flows = new Map();
  const protocols = new Map();
  let earliest = Infinity;
  let latest = -Infinity;
  let totalBytes = 0;
  for (const packet of packets) {
    if (packet.time !== null) {
      earliest = Math.min(earliest, packet.time);
      latest = Math.max(latest, packet.time);
    }
    totalBytes += packet.bytes;
    protocols.set(packet.kind, (protocols.get(packet.kind) ?? 0) + 1);
    const key = flowKey(packet);
    if (key) {
      if (!flows.has(key)) flows.set(key, { key, packets: 0, bytes: 0 });
      const flow = flows.get(key);
      flow.packets++;
      flow.bytes += packet.bytes;
    }
  }
  return {
    flows: [...flows.values()].sort((a, b) => b.packets - a.packets || a.key.localeCompare(b.key)),
    kinds: [...protocols].sort(([a], [b]) => a.localeCompare(b)),
    earliest: Number.isFinite(earliest) ? earliest : null,
    latest: Number.isFinite(latest) ? latest : null,
    totalBytes,
  };
}

const SYN = 2;
const ACK = 16;
const END = 5; // FIN or RST
const nextSeq = (seq) => (seq + 1) >>> 0;

export function firstHandshake(packets, key) {
  let initial;
  let reply;
  let repeats = 0;
  for (const packet of packets) {
    if (!packet.tcp || flowKey(packet) !== key) continue;
    const { flags, seq, ack } = packet.tcp;
    if (flags & END) {
      if (initial) break;
      continue;
    }
    const origin = endpoint(packet.source, packet.sourcePort);
    if ((flags & (SYN | ACK)) === SYN) {
      if (!initial) initial = { packet, origin };
      else if (origin === initial.origin && seq === initial.packet.tcp.seq) repeats++;
      else break;
      continue;
    }
    if (!initial) continue;
    if ((flags & (SYN | ACK)) === (SYN | ACK) && origin !== initial.origin && ack === nextSeq(initial.packet.tcp.seq)) {
      reply ??= packet;
    }
    if (reply && (flags & (SYN | ACK)) === ACK && origin === initial.origin &&
        seq === nextSeq(initial.packet.tcp.seq) && ack === nextSeq(reply.tcp.seq)) {
      return { syn: initial.packet, reply, ack: packet, repeats };
    }
  }
  return initial ? { syn: initial.packet, reply, ack: undefined, repeats } : null;
}

export function packetInWindow(time, earliest, range) {
  if (!range) return true;
  if (time === null || earliest === null) return false;
  const elapsed = Math.round((time - earliest) * 1000) / 1e6;
  return elapsed >= range.start && elapsed <= range.end;
}
