import { $, announce, downloadJSON, el, installTheme, stat, table, tag, wireDrop } from './ui.mjs';
import { MAX_CAPTURE } from './capture.mjs';
import { captureSummary, endpoint, firstHandshake, flowKey, packetInWindow } from './flows.mjs';
import { sampleCapture } from './sample.mjs';

const LIMIT = 30;
const FLOW_LIMIT = 15;
const formatter = new Intl.NumberFormat('en-CA');
let worker;
let generation = 0;
let report;
let summary;
let selected = null;
let page = 0;
let flowPage = 0;
let timeRange = null;

function size(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

function elapsed(time) {
  return time === null || summary.earliest === null ? 'Unavailable' : `+${((time - summary.earliest) / 1000).toFixed(3)} s`;
}

function visiblePackets() {
  const query = $('query').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const kind = $('protocol').value;
  return report.packets.filter((packet) => {
    if ((selected && selected !== flowKey(packet)) || (kind && kind !== packet.kind) ||
        !packetInWindow(packet.time, summary.earliest, timeRange)) return false;
    if (!query.length) return true;
    const string = [packet.protocol, packet.kind, packet.detail, endpoint(packet.source, packet.sourcePort),
      endpoint(packet.destination, packet.destinationPort)].filter(Boolean).join(' ').toLowerCase();
    return query.every((term) => string.includes(term));
  });
}

function packets() {
  if (!report) return;
  const filtered = visiblePackets();
  const pages = Math.max(1, Math.ceil(filtered.length / LIMIT));
  page = Math.min(page, pages - 1);
  table($('packets'), filtered.slice(page * LIMIT, (page + 1) * LIMIT).map((packet) => [
    packet.index, elapsed(packet.time), el('code', endpoint(packet.source, packet.sourcePort)),
    el('code', endpoint(packet.destination, packet.destinationPort)), tag(packet.kind),
    packet.detail ?? (packet.version ? `IPv${packet.version}` : 'Unavailable'), size(packet.captured),
  ]), 7, 'No packets match these filters.');
  $('record-count').textContent = `${formatter.format(filtered.length)} matching packets · Page ${page + 1} of ${pages}`;
  $('prev').disabled = page === 0;
  $('next').disabled = page + 1 >= pages;
  $('clear-flow').hidden = !selected;
  $('selected-flow').textContent = selected ? `Conversation filter: ${selected}` : '';
  timeline(filtered);
}

function flows(focusKey = null) {
  const remaining = summary.flows;
  const pages = Math.max(1, Math.ceil(remaining.length / FLOW_LIMIT));
  flowPage = Math.min(flowPage, pages - 1);
  let focusButton;
  table($('flows'), remaining.slice(flowPage * FLOW_LIMIT, (flowPage + 1) * FLOW_LIMIT).map((flow) => {
    const button = el('button', flow.key, 'flow-button');
    button.type = 'button';
    button.setAttribute('aria-pressed', String(flow.key === selected));
    if (flow.key === focusKey) focusButton = button;
    button.addEventListener('click', () => {
      selected = selected === flow.key ? null : flow.key;
      page = 0;
      flows(flow.key);
      packets();
      showHandshake();
    });
    return [button, formatter.format(flow.packets), size(flow.bytes)];
  }), 3, 'No IP addresses were available to group.');
  if (focusButton) focusButton.focus();
  $('flow-count').textContent = `${formatter.format(remaining.length)} conversations · Page ${flowPage + 1} of ${pages}`;
  $('flow-prev').disabled = flowPage === 0;
  $('flow-next').disabled = flowPage + 1 >= pages;
}

function timeline(filtered) {
  const canvas = $('timeline');
  const context = canvas.getContext('2d');
  if (!context) return;
  const width = canvas.width;
  const height = canvas.height;
  context.clearRect(0, 0, width, height);
  const timed = filtered.filter((item) => item.time !== null);
  if (!timed.length || summary.earliest === null) {
    $('timeline-note').textContent = 'No timestamps are available for these packets.';
    canvas.hidden = true;
    return;
  }
  canvas.hidden = false;
  const start = timeRange ? summary.earliest + timeRange.start * 1000 : summary.earliest;
  const end = timeRange ? summary.earliest + timeRange.end * 1000 : summary.latest;
  const range = end - start;
  const buckets = Array.from({ length: 48 }, () => 0);
  for (const packet of timed) {
    const bin = range ? Math.max(0, Math.min(buckets.length - 1, Math.floor((packet.time - start) / range * buckets.length))) : 0;
    buckets[bin]++;
  }
  context.fillStyle = getComputedStyle(canvas).getPropertyValue('--signal').trim();
  const max = Math.max(...buckets, 1);
  const cell = width / buckets.length;
  buckets.forEach((count, i) => {
    if (count) {
      const bar = Math.max(2, Math.round(count / max * (height - 6)));
      context.fillRect(i * cell + 1, height - bar, Math.max(1, cell - 2), bar);
    }
  });
  $('timeline-note').textContent = `${formatter.format(timed.length)} timestamped matches across ${(range / 1000).toFixed(3)} s. Peak bucket ${formatter.format(max)} packets.`;
}

function showHandshake() {
  $('tcp-report').hidden = !selected?.endsWith(' · TCP');
  const steps = $('tcp-steps');
  steps.replaceChildren();
  if ($('tcp-report').hidden) return;
  const found = firstHandshake(report.packets, selected);
  if (!found) {
    $('tcp-status').textContent = 'No initial SYN appears for these endpoints.';
    return;
  }
  const { syn, reply, ack, repeats } = found;
  let status = ack ? 'All three handshake packets observed.' : 'Only part of the handshake was observed.';
  if (ack && syn.time !== null && ack.time !== null && ack.time >= syn.time) {
    status += ` Observed SYN-to-ACK time ${(ack.time - syn.time).toFixed(3)} ms.`;
  }
  if (repeats) status += ` Repeated initial SYN records: ${formatter.format(repeats)}.`;
  $('tcp-status').textContent = status;
  for (const [name, packet] of [['SYN', syn], ['SYN-ACK', reply], ['ACK', ack]]) {
    if (packet) steps.append(el('li', `Packet ${packet.index} · ${name} · ${elapsed(packet.time)}`));
  }
}

function setTimeRange(range) {
  timeRange = range;
  page = 0;
  $('clear-time').disabled = !range;
  const status = $('time-status');
  status.dataset.state = 'ready';
  status.textContent = range ? `Showing ${range.start}–${range.end} seconds after the first timestamp.` : '';
  packets();
}

function show(value) {
  report = value;
  summary = captureSummary(value.packets);
  selected = null;
  page = 0;
  flowPage = 0;
  $('query').value = '';
  $('protocol').replaceChildren(new Option('All protocols', ''), ...summary.kinds.map(([label, count]) => new Option(`${label} · ${formatter.format(count)}`, label)));
  $('format').textContent = value.format;
  $('stats').replaceChildren(stat('Packet records', formatter.format(value.packets.length)),
    stat('IP conversations', formatter.format(summary.flows.length)), stat('Wire bytes reported', size(summary.totalBytes)),
    stat('Snapshot-shortened packets', formatter.format(value.snapshotGaps)));
  $('notes').replaceChildren(...value.notes.map((note) => el('li', note)));
  $('notes').hidden = !value.notes.length;
  $('report').hidden = false;
  flows();
  $('time-from').value = '';
  $('time-to').value = '';
  for (const id of ['apply-time', 'time-from', 'time-to']) $(id).disabled = summary.earliest === null;
  setTimeRange(null);
  showHandshake();
  announce(value.truncated ? 'Partial capture analyzed. See the capture notes.' : 'Capture analyzed locally. Choose a conversation to inspect its packets.');
}

function clear() {
  generation++;
  worker?.terminate();
  worker = null;
  report = undefined;
  summary = undefined;
  $('report').hidden = true;
  for (const id of ['flows', 'packets', 'notes', 'stats']) $(id).replaceChildren();
  announce('Open a capture or try the synthetic example.');
}

function analyse(buffer, current) {
  if (current !== generation) return;
  try {
    worker?.terminate();
    worker = new Worker(new URL('./worker.mjs', import.meta.url), { type: 'module' });
    const instance = worker;
    instance.addEventListener('message', (event) => {
      instance.terminate();
      if (current !== generation) return;
      worker = null;
      if (event.data.error) announce(event.data.error, true);
      else show(event.data.report);
    }, { once: true });
    instance.addEventListener('error', () => {
      instance.terminate();
      if (current !== generation) return;
      worker = null;
      announce('The local capture worker could not read this file.', true);
    }, { once: true });
    announce('Inspecting packet records in a background worker.');
    instance.postMessage(buffer, [buffer]);
  } catch (error) { announce(error.message, true); }
}

async function open(file) {
  const current = ++generation;
  worker?.terminate();
  worker = null;
  try {
    if (file.size > MAX_CAPTURE) throw new Error('Choose an uncompressed capture of 24 MiB or less.');
    announce('Reading the capture from your device.');
    analyse(await file.arrayBuffer(), current);
  } catch (error) {
    if (current === generation) announce(error.message, true);
  }
}

$('choose').addEventListener('click', () => $('file').click());
$('sample').addEventListener('click', () => analyse(sampleCapture(), ++generation));
$('clear').addEventListener('click', clear);
$('query').addEventListener('input', () => { page = 0; packets(); });
$('protocol').addEventListener('change', () => { page = 0; packets(); });
$('clear-flow').addEventListener('click', () => { selected = null; page = 0; flows(); packets(); showHandshake(); $('query').focus(); });
$('time-window').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!report || summary.earliest === null) return;
  const from = $('time-from');
  const to = $('time-to');
  const span = Math.round((summary.latest - summary.earliest) * 1000) / 1e6;
  const start = from.value === '' ? 0 : from.valueAsNumber;
  const end = to.value === '' ? span : to.valueAsNumber;
  if (from.validity.badInput || to.validity.badInput || !Number.isFinite(start) || !Number.isFinite(end) || start < 0 || start > end) {
    const status = $('time-status');
    status.dataset.state = 'error';
    status.textContent = 'Enter nonnegative seconds with the end at or after the start.';
    return;
  }
  setTimeRange(from.value === '' && to.value === '' ? null : { start, end });
});
$('clear-time').addEventListener('click', () => {
  $('time-from').value = '';
  $('time-to').value = '';
  setTimeRange(null);
  $('time-from').focus();
});
$('prev').addEventListener('click', () => { page--; packets(); });
$('next').addEventListener('click', () => { page++; packets(); });
$('flow-prev').addEventListener('click', () => { flowPage--; flows(); });
$('flow-next').addEventListener('click', () => { flowPage++; flows(); });
$('theme').addEventListener('click', () => requestAnimationFrame(() => { if (report) timeline(visiblePackets()); }));
$('export').addEventListener('click', () => {
  if (report) {
    const packets = visiblePackets().map(({ tcp, ...packet }) => packet);
    downloadJSON({ format: report.format, notes: report.notes, packets, elapsedSeconds: timeRange }, 'packet-pocket-report.json');
  }
});
wireDrop($('input'), $('file'), open);
installTheme();
