import { $, announce, downloadJSON, el, installTheme, stat, table, tag, wireDrop } from './ui.mjs';
import { MAX_CAPTURE } from './capture.mjs';
import { captureSummary, directionCounts, endpoint, firstHandshake, flowKey, packetInWindow } from './flows.mjs';
import { aggregate, captureMetrics, protocolComparison, timeBuckets } from './traffic.mjs';

const LIMIT = 30;
const FLOW_LIMIT = 15;
const formatter = new Intl.NumberFormat('en-CA');
const jobs = {primary:{id:0, worker:null}, secondary:{id:0, worker:null}};
let primaryName = '', secondaryName = '';
let primaryMetrics, secondaryMetrics;
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
  const {start, end} = timeBounds();
  const bins = timeBuckets(filtered, start, end);
  const timed = bins.reduce((sum, bin) => sum + bin.packets, 0);
  if (!timed) {
    $('timeline-note').textContent = 'No timestamps are available for these packets.';
    canvas.hidden = true;
    return;
  }
  canvas.hidden = false;
  const measure = $('timeline-measure').value;
  const unit = measure === 'packets' ? 'packets' : 'wire bytes';
  canvas.setAttribute('aria-label', unit + ' by equal time intervals');
  const buckets = bins.map(bin => bin[measure]);
  context.fillStyle = getComputedStyle(canvas).getPropertyValue('--signal').trim();
  const peak = Math.max(...buckets);
  const max = Math.max(1, peak);
  const cell = width / buckets.length;
  buckets.forEach((count, i) => {
    if (count) {
      const bar = Math.max(2, Math.round(count / max * (height - 6)));
      context.fillRect(i * cell + 1, height - bar, Math.max(1, cell - 2), bar);
    }
  });
  $('timeline-note').textContent = `${formatter.format(timed)} timestamped matches across ${((end - start) / 1000).toFixed(3)} s · ${bins.length} intervals · peak ${formatter.format(peak)} ${unit}.`;
}

function showHandshake() {
  $('direction-report').hidden = !selected;
  if (selected) table($('directions'), directionCounts(report.packets, selected).map(row => [
    row.from + ' → ' + row.to, formatter.format(row.records), size(row.wireBytes), size(row.capturedBytes),
  ]), 4, 'No recorded directions.');
  else $('directions').replaceChildren();
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

function show(value, filename) {
  removeComparison();
  primaryName = filename;
  primaryMetrics = captureMetrics(value);
  $('primary-name').textContent = filename;
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

function timeBounds() {
  if (summary.earliest === null) return {start:null, end:null};
  return timeRange ? {start:summary.earliest + timeRange.start * 1000, end:summary.earliest + timeRange.end * 1000}
    : {start:summary.earliest, end:summary.latest};
}

function stopJob(job) {
  job.id++;
  job.worker?.terminate();
  job.worker = null;
}

function removeComparison() {
  stopJob(jobs.secondary);
  secondaryMetrics = undefined;
  secondaryName = '';
  $('comparison').hidden = true;
  $('remove-second').hidden = true;
  $('compare-names').textContent = '';
  $('compare-metrics').replaceChildren();
  $('compare-protocols').replaceChildren();
  $('compare-notes').textContent = '';
  $('compare-status').textContent = 'You can also drop the second file here.';
  $('compare-status').dataset.state = 'ready';
}

function metricValue(value, unit, signed = false) {
  if (value === null) return 'Unavailable';
  const sign = signed && value > 0 ? '+' : '';
  return sign + formatter.format(value) + (unit ? ' ' + unit : '');
}

function displayComparison(metrics, filename) {
  secondaryMetrics = metrics;
  secondaryName = filename;
  $('remove-second').hidden = false;
  $('comparison').hidden = false;
  $('compare-names').textContent = 'First: ' + primaryName + ' · Second: ' + secondaryName;
  const messages = [[primaryMetrics, 'First'], [metrics, 'Second']].flatMap(([capture, label]) =>
    capture.parserNotes.map(note => label + ' capture: ' + note));
  $('compare-notes').textContent = messages.join(' ');
  $('compare-status').textContent = 'Comparison ready.';
  $('compare-status').dataset.state = 'ready';
  const rows = [
    ['Packet records','records',''], ['Reported wire bytes','wireBytes','B'], ['Captured bytes','capturedBytes','B'],
    ['Shortened by snapshot','shortened',''], ['Missing timestamp','missingTimestamps',''],
    ['Timestamp span','spanSeconds','s'], ['Timestamped packets / second','packetsPerSecond',''],
    ['Timestamped wire bytes / second','wireBytesPerSecond','B/s'],
  ].map(([label, key, unit]) => {
    const first = primaryMetrics[key], second = metrics[key];
    return [label, metricValue(first, unit), metricValue(second, unit),
      metricValue(first === null || second === null ? null : second - first, unit, true)];
  });
  table($('compare-metrics'), rows, 4, '');
  table($('compare-protocols'), protocolComparison(primaryMetrics, metrics).map(row => [
    row.kind, formatter.format(row.primaryPackets) + ' · ' + metricValue(row.primaryPercent, '%'),
    formatter.format(row.secondaryPackets) + ' · ' + metricValue(row.secondaryPercent, '%'),
    metricValue(row.changePoints, 'pp', true),
  ]), 4, 'Neither capture contains packet records.');
}

function clear() {
  stopJob(jobs.primary);
  removeComparison();
  report = undefined;
  summary = undefined;
  primaryMetrics = undefined;
  primaryName = '';
  $('primary-name').textContent = '';
  $('report').hidden = true;
  for (const id of ['flows', 'packets', 'notes', 'stats', 'tcp-steps', 'selected-flow', 'directions', 'record-count', 'flow-count', 'timeline-note', 'tcp-status']) $(id).replaceChildren();
  $('query').value = '';
  $('time-from').value = '';
  $('time-to').value = '';
  selected = null;
  timeRange = null;
  announce('Choose a file from your device to begin.');
}

async function open(file, secondary = false) {
  if (secondary && !report) return;
  const job = secondary ? jobs.secondary : jobs.primary;
  stopJob(job);
  const ticket = job.id;
  const status = (message, error = false) => {
    if (!secondary) { announce(message, error); return; }
    $('compare-status').textContent = message;
    $('compare-status').dataset.state = error ? 'error' : 'ready';
  };
  try {
    if (file.size > MAX_CAPTURE) throw new Error('Choose an uncompressed capture of 24 MiB or less.');
    status('Reading ' + file.name + ' locally…');
    if (secondary) $('remove-second').hidden = false;
    const buffer = await file.arrayBuffer();
    if (ticket !== job.id) return;
    const instance = new Worker(new URL('./worker.mjs', import.meta.url), {type:'module'});
    job.worker = instance;
    instance.addEventListener('message', ({data}) => {
      instance.terminate();
      if (ticket !== job.id) return;
      job.worker = null;
      if (data.error) status(data.error, true);
      else if (secondary) displayComparison(data.metrics, file.name);
      else show(data.report, file.name);
    }, {once:true});
    instance.addEventListener('error', () => {
      instance.terminate();
      if (ticket !== job.id) return;
      job.worker = null;
      status('The local worker could not read this capture.', true);
    }, {once:true});
    instance.postMessage({buffer, summaryOnly:secondary}, [buffer]);
  } catch (error) {
    if (ticket === job.id) status(error.message, true);
  }
}

$('choose').addEventListener('click', () => $('file').click());
$('choose-second').addEventListener('click', () => $('second-file').click());
$('remove-second').addEventListener('click', removeComparison);
$('timeline-measure').addEventListener('change', () => timeline(visiblePackets()));
$('compare-export').addEventListener('click', () => {
  if (!secondaryMetrics) return;
  downloadJSON({first:primaryMetrics, second:secondaryMetrics, protocols:protocolComparison(primaryMetrics, secondaryMetrics)},
    'packet-pocket-comparison.json');
});
$('aggregate-export').addEventListener('click', () => {
  if (!report) return;
  const filtered = visiblePackets(), {start, end} = timeBounds();
  const bins = timeBuckets(filtered, start, end);
  downloadJSON({sourceFormat:report.format, captureStoppedEarly:report.truncated, parserNotes:report.notes,
    summary:aggregate(filtered), timeline:{startSeconds:start === null ? null : (start - summary.earliest) / 1000,
      endSeconds:end === null ? null : (end - summary.earliest) / 1000, bins}}, 'packet-pocket-aggregate.json');
});
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
  if (from.validity.badInput || to.validity.badInput || !Number.isFinite(start) || !Number.isFinite(summary.earliest + end * 1000) || start < 0 || start > end) {
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
wireDrop($('compare-input'), $('second-file'), file => open(file, true));
installTheme();
