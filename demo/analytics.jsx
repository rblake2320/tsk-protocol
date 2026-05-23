// analytics.jsx — Lightweight client-side event tracker.
// POSTs structured events to the local server for persistence.
// No third-party scripts. No external calls. Everything stays local.

const ANALYTICS_ENDPOINT = `${window.SERVER || 'http://localhost:3200'}/analytics/event`;

// Session ID — one UUID per browser tab session
const SESSION_ID = crypto.randomUUID();
const SESSION_START = Date.now();

// Queue failed events for retry (server might not be up yet)
const _queue = [];
let _flushing = false;

async function _flush() {
  if (_flushing || _queue.length === 0) return;
  _flushing = true;
  while (_queue.length > 0) {
    const evt = _queue[0];
    try {
      await fetch(ANALYTICS_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(evt),
        keepalive: true,
      });
      _queue.shift();
    } catch {
      break; // server not reachable, stop flushing
    }
  }
  _flushing = false;
}

function trackEvent(name, data = {}) {
  const evt = {
    event: name,
    session: SESSION_ID,
    ts: Date.now(),
    sessionAge: Date.now() - SESSION_START,
    url: location.href,
    site: 'tsk',
    ...data,
  };
  _queue.push(evt);
  _flush();
}

// Auto-track: page visibility changes (tab hidden/shown = engagement signal)
document.addEventListener('visibilitychange', () => {
  trackEvent('visibility_change', { hidden: document.hidden });
});

// Auto-track: page unload with total session duration
window.addEventListener('beforeunload', () => {
  trackEvent('session_end', { durationMs: Date.now() - SESSION_START });
});

// Expose globally so all screens can call trackEvent(...)
window.trackEvent = trackEvent;
