import {readCapture} from './capture.mjs';
import {captureMetrics} from './traffic.mjs';

self.addEventListener('message', ({data}) => {
  try {
    const report = readCapture(data.buffer);
    if (data.summaryOnly) self.postMessage({metrics:captureMetrics(report)});
    else self.postMessage({report});
  } catch (error) { self.postMessage({error:error.message}); }
});
