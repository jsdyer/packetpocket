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
