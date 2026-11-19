// Aggregate records without retaining endpoint, hostname or packet-level details.
export function aggregate(packets) {
  const kinds = new Map();
  let wireBytes = 0, capturedBytes = 0, shortened = 0;
  let timedBytes = 0, timestamped = 0;
  let first = Infinity, last = -Infinity;
  for (const packet of packets) {
    wireBytes += packet.bytes;
    capturedBytes += packet.captured;
    if (packet.bytes > packet.captured) shortened++;
    if (Number.isFinite(packet.time)) {
      timestamped++;
      timedBytes += packet.bytes;
      first = Math.min(first, packet.time);
      last = Math.max(last, packet.time);
    }
    const kind = packet.kind;
    if (!kinds.has(kind)) kinds.set(kind, {kind, packets:0, wireBytes:0});
    const group = kinds.get(kind);
    group.packets++;
    group.wireBytes += packet.bytes;
  }
  const spanSeconds = timestamped ? (last - first) / 1000 : null;
  const protocols = [...kinds.values()].sort((a, b) => b.packets - a.packets || a.kind.localeCompare(b.kind));
  return {records:packets.length, wireBytes, capturedBytes, shortened,
    timestamped, missingTimestamps:packets.length - timestamped, spanSeconds,
    packetsPerSecond:spanSeconds > 0 ? timestamped / spanSeconds : null,
    wireBytesPerSecond:spanSeconds > 0 ? timedBytes / spanSeconds : null, protocols};
}

export function captureMetrics(report) {
  return {format:report.format, stoppedEarly:report.truncated, parserNotes:report.notes, ...aggregate(report.packets)};
}

export function timeBuckets(packets, start, end, count = 48) {
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return [];
  const duration = end - start;
  const bins = Array.from({length:duration ? count : 1}, () => ({packets:0, wireBytes:0}));
  for (const packet of packets) {
    if (!Number.isFinite(packet.time) || packet.time < start || packet.time > end) continue;
    const index = duration ? Math.min(count - 1, Math.floor((packet.time - start) / duration * count)) : 0;
    bins[index].packets++;
    bins[index].wireBytes += packet.bytes;
  }
  return bins;
}

export function protocolComparison(primary, secondary) {
  const before = new Map(primary.protocols.map(row => [row.kind, row.packets]));
  const after = new Map(secondary.protocols.map(row => [row.kind, row.packets]));
  return [...new Set([...before.keys(), ...after.keys()])].sort().map(kind => {
    const primaryPackets = before.get(kind) ?? 0, secondaryPackets = after.get(kind) ?? 0;
    const primaryPercent = primary.records ? primaryPackets / primary.records * 100 : null;
    const secondaryPercent = secondary.records ? secondaryPackets / secondary.records * 100 : null;
    const changePoints = primaryPercent !== null && secondaryPercent !== null ? secondaryPercent - primaryPercent : null;
    return {kind, primaryPackets, secondaryPackets, primaryPercent, secondaryPercent, changePoints};
  });
}
