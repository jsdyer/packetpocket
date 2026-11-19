import test from 'node:test';
import assert from 'node:assert/strict';
import { readCapture } from '../web/capture.mjs';
import { decodeFrame } from '../web/packet.mjs';
import { captureSummary, endpoint, firstHandshake, flowKey, packetInWindow } from '../web/flows.mjs';
import { sampleCapture, samplePackets } from './fixtures/captures.mjs';

function pcapng(packet, little) {
  const padded = (packet.length + 3) & ~3;
  const block = 32 + padded;
  const buffer = new ArrayBuffer(28 + 28 + block);
  const view = new DataView(buffer);
  const u32 = (position, value) => view.setUint32(position, value, little);
  const u16 = (position, value) => view.setUint16(position, value, little);
  u32(0, 0x0a0d0d0a);
  u32(4, 28);
  u32(8, 0x1a2b3c4d);
  u16(12, 1);
  u32(16, 0xffffffff);
  u32(20, 0xffffffff);
  u32(24, 28);
  u32(28, 1);
  u32(32, 28);
  u16(36, 1);
  u32(40, 65535);
  u16(44, 9);
  u16(46, 1);
  view.setUint8(48, 3);
  u32(52, 28);
  u32(56, 6);
  u32(60, block);
  u32(72, 12345);
  u32(76, packet.length);
  u32(80, packet.length + 5);
  new Uint8Array(buffer, 84, packet.length).set(packet);
  u32(56 + block - 4, block);
  return buffer;
}

test('decoded example has both DNS, both HTTP and one TLS record across all classic endian/timestamp variants', () => {
  for (const little of [true, false]) for (const nano of [true, false]) {
    const report = readCapture(sampleCapture({ little, nano }));
    assert.equal(report.packets.length, 8);
    assert.deepEqual(report.packets.map((packet) => packet.kind), ['DNS', 'DNS', 'TCP', 'TCP', 'TCP', 'HTTP', 'HTTP', 'TLS']);
    assert.match(report.packets[7].detail, /TLS 1.3 offered · demo.example/);
    assert.doesNotMatch(JSON.stringify(report), /ignored|example\?|Location|MOVED/);
    assert.equal(report.packets[0].time, 1735689600000.935);
    const summary = captureSummary(report.packets);
    assert.equal(summary.flows.length, 3);
    assert.equal(flowKey(report.packets[0]), flowKey(report.packets[1]));
    assert.ok(summary.totalBytes > 350);
  }
});

test('enhanced PCAPNG records honor the interface resolution and snap length', () => {
  for (const little of [true, false]) {
    const record = readCapture(pcapng(samplePackets()[0], little));
    assert.equal(record.format, 'PCAPNG');
    assert.equal(record.packets[0].time, 12345);
    assert.equal(record.snapshotGaps, 1);
    assert.equal(record.truncated, false);
    assert.equal(record.packets[0].detail, 'Query · demo.example · A');
  }
});

test('reads raw IPv6 and wraps its endpoint with a port', () => {
  const bytes = new Uint8Array(48);
  bytes.set([0x60, 0, 0, 0, 0, 8, 17, 64]);
  bytes.set([0x20, 1, 0x0d, 0xb8], 8);
  bytes[23] = 1;
  bytes.set([0x20, 1, 0x0d, 0xb8], 24);
  bytes[39] = 2;
  bytes.set([0x12, 0x34, 0x09, 0x33, 0, 8], 40);
  const packet = decodeFrame(bytes, 101);
  assert.equal(packet.source, '2001:db8::1');
  assert.equal(packet.destination, '2001:db8::2');
  assert.equal(endpoint(packet.source, packet.sourcePort), '[2001:db8::1]:4660');
});

test('rejects arbitrary input and reports a truncated trailing record', () => {
  assert.throws(() => readCapture(new ArrayBuffer(20)), /Unknown capture format/);
  const sample = sampleCapture();
  const report = readCapture(sample.slice(0, -5));
  assert.equal(report.packets.length, 7);
  assert.equal(report.truncated, true);
  assert.match(report.notes[0], /incomplete final record/);
});

test('matches a conventional TCP handshake and keeps partial evidence separate', () => {
  const { packets } = readCapture(sampleCapture());
  const [, , syn, reply, ack] = packets;
  const key = flowKey(syn);
  const result = firstHandshake(packets, key);
  assert.deepEqual(result, { syn, reply, ack, repeats: 0 });
  assert.equal(result.ack.time - result.syn.time, 124);
  const incorrect = { ...ack, tcp: { ...ack.tcp, ack: 842 } };
  assert.deepEqual(firstHandshake([syn, syn, reply, incorrect], key), { syn, reply, ack: undefined, repeats: 1 });
  assert.equal(firstHandshake([reply, ack], key), null);
  assert.equal(packetInWindow(reply.time, packets[0].time, { start: 0.125, end: 0.186 }), true);
  assert.equal(packetInWindow(ack.time, packets[0].time, { start: 0.125, end: 0.186 }), false);
  assert.equal(packetInWindow(null, packets[0].time, { start: 0, end: 1 }), false);
});

test('relative traffic bins include both ends, omit untimed packets and distinguish bytes from counts', async () => {
  const {aggregate,timeBuckets} = await import('../web/traffic.mjs');
  const packets = [
    {time:2000,bytes:90,captured:90,kind:'TCP'},
    {time:1000,bytes:10,captured:5,kind:'UDP'},
    {time:null,bytes:200,captured:20,kind:'TCP'},
  ];
  const totals = aggregate(packets);
  assert.deepEqual([totals.records, totals.wireBytes, totals.capturedBytes, totals.shortened], [3,300,115,2]);
  assert.deepEqual([totals.missingTimestamps, totals.spanSeconds, totals.packetsPerSecond, totals.wireBytesPerSecond], [1,1,2,100]);
  assert.deepEqual(timeBuckets(packets,1000,2000,2), [{packets:1,wireBytes:10},{packets:1,wireBytes:90}]);
  assert.deepEqual(timeBuckets(packets,2000,2000), [{packets:1,wireBytes:90}]);
  assert.deepEqual(timeBuckets(packets,null,null), []);
});

test('compares PCAP and PCAPNG protocol shares while preserving partial, empty and zero-time cases', async () => {
  const {captureMetrics,protocolComparison} = await import('../web/traffic.mjs');
  const example = sampleCapture(), first = captureMetrics(readCapture(example));
  const second = captureMetrics(readCapture(pcapng(samplePackets()[0],false)));
  assert.equal(second.packetsPerSecond, null);
  assert.equal(second.shortened, 1);
  assert.equal(captureMetrics(readCapture(example.slice(0,-1))).stoppedEarly, true);
  const blank = captureMetrics(readCapture(example.slice(0,24)));
  assert.deepEqual([blank.records,blank.spanSeconds,blank.wireBytesPerSecond],[0,null,null]);
  assert.equal(protocolComparison(blank,second)[0].changePoints,null);
  const dns = protocolComparison(first,second).find(row => row.kind==='DNS');
  assert.deepEqual(dns, {kind:'DNS',primaryPackets:2,secondaryPackets:1,primaryPercent:25,secondaryPercent:100,changePoints:75});
  const shareable = JSON.stringify({first,second,protocols:protocolComparison(first,second)});
  assert.doesNotMatch(shareable,/192\.0\.2|demo\.example|1735689600|endpoint|sourcePort|source|destination|payload|detail|host/i);
});

test('reads PCAPNG simple blocks without inventing timestamps or rates', async () => {
  const {captureMetrics} = await import('../web/traffic.mjs');
  const frame = samplePackets()[0];
  const idb = new Uint8Array(pcapng(frame,true),0,56);
  const size = 16 + ((frame.length+3)&~3);
  const buffer = new ArrayBuffer(idb.byteLength+size), b = new Uint8Array(buffer), v = new DataView(buffer);
  b.set(idb); v.setUint32(56,3,true); v.setUint32(60,size,true); v.setUint32(64,frame.length,true); b.set(frame,68); v.setUint32(buffer.byteLength-4,size,true);
  const metrics = captureMetrics(readCapture(buffer));
  assert.deepEqual([metrics.records,metrics.timestamped,metrics.missingTimestamps,metrics.spanSeconds,metrics.packetsPerSecond],[1,0,1,null,null]);
});

test('direction totals name a missing reverse direction and preserve the overall packet count', async () => {
  const {directionCounts} = await import('../web/flows.mjs');
  const {packets} = readCapture(sampleCapture());
  const key = flowKey(packets[0]);
  assert.deepEqual(directionCounts(packets,key).map(row=>row.records),[1,1]);
  assert.deepEqual(directionCounts(packets.slice(0,1),key).map(row=>row.records),[1,0]);
  assert.deepEqual(directionCounts([],key),[]);
});
