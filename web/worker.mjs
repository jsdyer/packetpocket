import { readCapture } from './capture.mjs';

self.addEventListener('message', (event) => {
  try { self.postMessage({ report: readCapture(event.data) }); }
  catch (error) { self.postMessage({ error: error.message }); }
});
