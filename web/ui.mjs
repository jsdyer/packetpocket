export const $ = (id) => document.getElementById(id);

export function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

export function announce(message, error = false) {
  const status = $('status');
  status.textContent = message;
  status.dataset.state = error ? 'error' : 'ready';
}

export function stat(label, value) {
  const box = el('div', undefined, 'stat');
  box.append(el('strong', String(value)), el('span', label));
  return box;
}

export function tag(text, level) {
  const node = el('span', text, 'tag');
  if (level) node.dataset.level = level;
  return node;
}

export function table(tbody, rows, columns, message) {
  const result = rows.map((values) => {
    const tr = el('tr');
    for (const value of values) {
      const td = el('td');
      if (typeof value === 'string' || typeof value === 'number') td.textContent = value;
      else if (value) td.append(value);
      else td.textContent = '—';
      tr.append(td);
    }
    return tr;
  });
  if (!result.length) {
    const tr = el('tr');
    const td = el('td', message, 'table-empty');
    td.colSpan = columns;
    tr.append(td);
    result.push(tr);
  }
  tbody.replaceChildren(...result);
}

export function downloadJSON(value, filename) {
  const blob = new Blob([JSON.stringify(value, null, 2) + '\n'], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = el('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function installTheme() {
  const button = $('theme');
  function setTheme(dark) {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    button.setAttribute('aria-pressed', String(dark));
  }
  try { setTheme(localStorage.getItem('coolcode-theme') === 'dark'); } catch { setTheme(false); }
  button.hidden = false;
  button.addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme !== 'dark';
    setTheme(dark);
    try { localStorage.setItem('coolcode-theme', dark ? 'dark' : 'light'); } catch { /* Theme stays in memory. */ }
  });
}

export function wireDrop(target, picker, accept) {
  picker.addEventListener('change', () => {
    if (picker.files.length) accept(picker.files[0]);
    picker.value = '';
  });
  target.addEventListener('dragover', (event) => {
    if (Array.from(event.dataTransfer.types).includes('Files')) event.preventDefault();
  });
  target.addEventListener('drop', (event) => {
    if (!event.dataTransfer.files.length) return;
    event.preventDefault();
    accept(event.dataTransfer.files[0]);
  });
}
