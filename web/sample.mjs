const encoder = new TextEncoder();
const local = [192, 0, 2, 7];
const resolver = [198, 51, 100, 53];
const website = [203, 0, 113, 80];

function join(...items) {
  const result = new Uint8Array(items.reduce((size, item) => size + item.length, 0));
  let offset = 0;
  for (const item of items) { result.set(item, offset); offset += item.length; }
  return result;
}
const be = (value) => [(value >> 8) & 255, value & 255];

function ethernet(source, target, from, to, tcp, payload) {
  const ethernetHeader = new Uint8Array(14);
  ethernetHeader.set([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0]);
  const transport = new Uint8Array(tcp ? 20 : 8);
  transport.set([...be(from), ...be(to)]);
  if (tcp) transport.set([0x50, 0x18], 12);
  else transport.set(be(transport.length + payload.length), 4);
  const ip = new Uint8Array(20);
  ip.set([0x45, 0, ...be(ip.length + transport.length + payload.length), 0, 1, 0, 0, 64, tcp ? 6 : 17]);
  ip.set(source, 12);
  ip.set(target, 16);
  return join(ethernetHeader, ip, transport, payload);
}

function dnsPayload(response) {
  const question = [4, 100, 101, 109, 111, 7, 101, 120, 97, 109, 112, 108, 101, 0, 0, 1, 0, 1];
  const header = [0x88, 0x46, response ? 0x81 : 0x01, response ? 0x80 : 0, 0, 1, 0, response ? 1 : 0, 0, 0, 0, 0];
  const answer = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...website];
  return join(header, question, response ? answer : []);
}

function hello() {
  const name = encoder.encode('demo.example');
  const sni = join(be(3 + name.length), [0, ...be(name.length)], name);
  const extensions = join([0, 0, ...be(sni.length)], sni, [0, 43, 0, 3, 2, 3, 4]);
  const body = join([3, 3], new Uint8Array(32), [0, 0, 2, 0x13, 1, 1, 0], be(extensions.length), extensions);
  return join([22, 3, 1, ...be(body.length + 4), 1, 0, ...be(body.length)], body);
}

export function samplePackets() {
  return [
    ethernet(local, resolver, 50531, 53, false, dnsPayload(false)),
    ethernet(resolver, local, 53, 50531, false, dnsPayload(true)),
    ethernet(local, website, 50004, 80, true, encoder.encode('GET /example?ignored=yes HTTP/1.1\r\nHost: demo.example\r\n\r\n')),
    ethernet(website, local, 80, 50004, true, encoder.encode('HTTP/1.1 301 Moved Permanently\r\nLocation: https://demo.example/\r\n\r\n')),
    ethernet(local, website, 50005, 443, true, hello()),
  ];
}

export function sampleCapture({ little = true, nano = false } = {}) {
  const packets = samplePackets();
  const size = packets.reduce((total, packet) => total + 16 + packet.length, 24);
  const raw = new ArrayBuffer(size);
  const view = new DataView(raw);
  view.setUint32(0, nano ? 0xa1b23c4d : 0xa1b2c3d4, little);
  view.setUint16(4, 2, little);
  view.setUint16(6, 4, little);
  view.setUint32(16, 65535, little);
  view.setUint32(20, 1, little);
  let offset = 24;
  for (const [i, packet] of packets.entries()) {
    view.setUint32(offset, 1735689600, little);
    view.setUint32(offset + 4, (i * 62000 + 935) * (nano ? 1000 : 1), little);
    view.setUint32(offset + 8, packet.length, little);
    view.setUint32(offset + 12, packet.length, little);
    new Uint8Array(raw, offset + 16, packet.length).set(packet);
    offset += 16 + packet.length;
  }
  return raw;
}
