import { decodeFrame } from './packet.mjs';

export const MAX_CAPTURE = 24 * 1024 * 1024;
const MAX_PACKETS = 50000;
const LINK_MASK = 0xffff;
const FORMATS = new Map([
  [0xd4c3b2a1, { little: true, divisor: 1000 }], [0xa1b2c3d4, { little: false, divisor: 1000 }],
  [0x4d3cb2a1, { little: true, divisor: 1000000 }], [0xa1b23c4d, { little: false, divisor: 1000000 }],
]);

function collection(format) {
  return { format, packets: [], notes: [], truncated: false, snapshotGaps: 0 };
}

function add(result, data, link, time, originalLength) {
  const entry = decodeFrame(data, link);
  result.packets.push({ index: result.packets.length + 1, time, bytes: originalLength, captured: data.length, ...entry });
  if (originalLength > data.length) result.snapshotGaps++;
}

function pcap(bytes, view, format) {
  if (bytes.length < 24) throw new Error('The PCAP file header is incomplete.');
  const { little, divisor } = format;
  if (view.getUint16(4, little) !== 2 || view.getUint16(6, little) !== 4) throw new Error('Only classic PCAP version 2.4 is supported.');
  const link = view.getUint32(20, little) & LINK_MASK;
  const result = collection('PCAP');
  let offset = 24;
  for (; offset + 16 <= bytes.length && result.packets.length < MAX_PACKETS;) {
    const seconds = view.getUint32(offset, little);
    const fraction = view.getUint32(offset + 4, little);
    const captured = view.getUint32(offset + 8, little);
    const length = view.getUint32(offset + 12, little);
    const start = offset + 16;
    const end = start + captured;
    if (end > bytes.length || length < captured) break;
    add(result, bytes.subarray(start, end), link, seconds * 1000 + fraction / divisor, length);
    offset = end;
  }
  if (offset < bytes.length) {
    result.truncated = true;
    result.notes.push(result.packets.length === MAX_PACKETS ? 'Packet count limit reached.' : 'Reading stopped at a malformed or incomplete final record.');
  }
  return result;
}

function interfaceInfo(view, start, end, little) {
  const info = { link: view.getUint16(start, little), snaplen: view.getUint32(start + 4, little), units: 1e6, offset: 0 };
  for (let i = start + 8; i + 4 <= end;) {
    const code = view.getUint16(i, little);
    const length = view.getUint16(i + 2, little);
    const option = i + 4;
    if (!code || option + length > end) break;
    if (code === 9 && length === 1) {
      const value = view.getUint8(option);
      info.units = value & 128 ? 2 ** (value & 127) : 10 ** value;
    }
    if (code === 14 && length === 8) info.offset = Number(view.getBigInt64(option, little));
    i = option + ((length + 3) & ~3);
  }
  return info;
}

function pcapng(bytes, view) {
  const result = collection('PCAPNG');
  let offset = 0;
  let little = null;
  let interfaces = [];
  let ignored = 0;
  for (; offset + 12 <= bytes.length && result.packets.length < MAX_PACKETS;) {
    const section = view.getUint32(offset) === 0x0a0d0d0a;
    if (section) {
      const order = view.getUint32(offset + 8);
      if (order !== 0x1a2b3c4d && order !== 0x4d3c2b1a) break;
      little = order === 0x4d3c2b1a;
      interfaces = [];
    }
    if (little === null) break;
    const type = view.getUint32(offset, little);
    const size = view.getUint32(offset + 4, little);
    const end = offset + size;
    if (size < 12 || size % 4 || end > bytes.length || view.getUint32(end - 4, little) !== size) break;
    if (section) {
      if (size < 28 || view.getUint16(offset + 12, little) !== 1) break;
    } else if (type === 1 && size >= 20) interfaces.push(interfaceInfo(view, offset + 8, end - 4, little));
    else if (type === 6 && size >= 32) {
      const info = interfaces[view.getUint32(offset + 8, little)];
      const ticks = view.getUint32(offset + 12, little) * 2 ** 32 + view.getUint32(offset + 16, little);
      const captured = view.getUint32(offset + 20, little);
      const length = view.getUint32(offset + 24, little);
      const start = offset + 28;
      if (info && start + captured <= end - 4 && length >= captured) {
        const ms = (ticks / info.units + info.offset) * 1000;
        add(result, bytes.subarray(start, start + captured), info.link, Math.abs(ms) <= 8.64e15 ? ms : null, length);
      } else ignored++;
    } else if (type === 3 && size >= 16 && interfaces.length) {
      const length = view.getUint32(offset + 8, little);
      const start = offset + 12;
      const captured = Math.min(length, interfaces[0].snaplen || length, end - 4 - start);
      add(result, bytes.subarray(start, start + captured), interfaces[0].link, null, length);
    } else if (type === 2) ignored++;
    offset = end;
  }
  if (offset < bytes.length) {
    result.truncated = true;
    result.notes.push(result.packets.length === MAX_PACKETS ? 'Packet count limit reached.' : 'Reading stopped at a malformed or incomplete block.');
  }
  if (ignored) result.notes.push(`${ignored} packet blocks used an unavailable interface or an unsupported format.`);
  return result;
}

export function readCapture(buffer) {
  if (!(buffer instanceof ArrayBuffer) || buffer.byteLength < 4) throw new Error('Choose a nonempty PCAP or PCAPNG file.');
  if (buffer.byteLength > MAX_CAPTURE) throw new Error('Choose a capture of 24 MiB or less.');
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const magic = view.getUint32(0);
  const format = FORMATS.get(magic);
  const result = format ? pcap(bytes, view, format) : magic === 0x0a0d0d0a ? pcapng(bytes, view) : null;
  if (!result) throw new Error('Unknown capture format. Choose an uncompressed PCAP or PCAPNG file.');
  if (!result.packets.length && (result.truncated || result.notes.length)) throw new Error('No supported packet records were found before an incomplete or unsupported record.');
  return result;
}
