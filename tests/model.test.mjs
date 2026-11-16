import test from 'node:test';
import assert from 'node:assert/strict';
import { readCapture } from '../web/capture.mjs';
import { decodeFrame } from '../web/packet.mjs';
import { captureSummary, endpoint, flowKey } from '../web/flows.mjs';
import { sampleCapture, samplePackets } from '../web/sample.mjs';

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
    assert.equal(report.packets.length, 5);
    assert.deepEqual(report.packets.map((packet) => packet.kind), ['DNS', 'DNS', 'HTTP', 'HTTP', 'TLS']);
    assert.match(report.packets[4].detail, /TLS 1.3 offered · demo.example/);
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
  assert.equal(report.packets.length, 4);
  assert.equal(report.truncated, true);
  assert.match(report.notes[0], /incomplete final record/);
});
