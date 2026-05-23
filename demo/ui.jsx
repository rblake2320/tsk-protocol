// ui.jsx — Shared UI primitives: Logo, KeyGlyph, Sparkline, Ring, Pill, etc.

const { useState, useEffect, useRef, useMemo, useCallback } = React;

// ── Logo ────────────────────────────────────────────────────────────────────
function Logo({ size = 24 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
      <rect x="1" y="1" width="26" height="26" rx="7" stroke="currentColor" strokeOpacity=".25" />
      <g transform="translate(14 14)">
        <rect x="-9" y="-2" width="6" height="4" rx="1" fill="var(--static)" />
        <rect x="-2" y="-2" width="5" height="4" rx="1" fill="var(--totp)" />
        <rect x="4"  y="-2" width="5" height="4" rx="1" fill="var(--hotp)" />
        <circle cx="0" cy="0" r="10.5" stroke="currentColor" strokeOpacity=".15" />
      </g>
    </svg>
  );
}

// ── KeyGlyph: tumbler key rendered as colored segments ──────────────────────
// parts: { id: charString }, map: tumbler map (gives segment metadata)
// view = 'server' (shows positions/types) | 'client' (flat, no info) | 'attacker' (flat, no info)
function KeyGlyph({ map, parts, view = 'server', flashing = {}, showLabels = false }) {
  if (!map || !parts) return null;
  const ordered = map.segments.slice().sort((a, b) => a.position[0] - b.position[0]);

  if (view === 'client' || view === 'attacker') {
    // flat string — no segment info revealed
    const full = ordered.map((s) => parts[s.id] || '').join('');
    return (
      <div className="key flat mono" style={{ wordBreak: 'break-all', fontSize: 14, gap: 0 }}>
        <span className="seg" style={{ color: view === 'attacker' ? 'var(--muted)' : 'var(--text)' }}>
          {full}
        </span>
      </div>
    );
  }

  return (
    <div className="key" style={{ position: 'relative', marginTop: showLabels ? 18 : 0 }}>
      {ordered.map((s) => (
        <span
          key={s.id}
          className={`seg ${s.type} ${flashing[s.id] ? 'flash' : ''}`}
          title={`${s.type.toUpperCase()} · pos [${s.position[0]}, ${s.position[1]})${
            s.windowSec ? ` · ${s.windowSec}s window` : ''
          }`}
        >
          {showLabels && <span className="lbl">{s.label}</span>}
          {parts[s.id] || '·'.repeat(s.length)}
        </span>
      ))}
    </div>
  );
}

// ── Progress ring (countdown for TOTP) ──────────────────────────────────────
function Ring({ progress = 0, size = 36, stroke = 3, color }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  return (
    <svg className="ring" width={size} height={size}>
      <circle className="bg" cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} />
      <circle
        className="fg"
        cx={size / 2}
        cy={size / 2}
        r={r}
        strokeWidth={stroke}
        strokeDasharray={c}
        strokeDashoffset={c * (1 - progress)}
        style={{ stroke: color || 'var(--totp)' }}
        strokeLinecap="round"
      />
    </svg>
  );
}

// ── Sparkline ───────────────────────────────────────────────────────────────
function Sparkline({ data = [], width = 120, height = 32, color = 'var(--primary)', fill = true }) {
  if (data.length < 2) return <svg width={width} height={height} />;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const step = width / (data.length - 1);
  const pts = data.map((v, i) => [i * step, height - ((v - min) / range) * (height - 4) - 2]);
  const d = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');
  const fillD = fill ? `${d} L${width} ${height} L0 ${height} Z` : null;
  return (
    <svg width={width} height={height}>
      {fill && <path d={fillD} fill={color} opacity=".14" />}
      <path d={d} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// ── Threat gauge (0-100 arc) ────────────────────────────────────────────────
function ThreatGauge({ score = 0, verdict = 'clean', size = 180 }) {
  const r = size / 2 - 14;
  const c = Math.PI * r; // half circle
  const off = c * (1 - score / 100);
  const color =
    verdict === 'attack' ? 'var(--danger)' :
    verdict === 'suspicious' ? 'var(--warning)' : 'var(--success)';
  return (
    <div style={{ position: 'relative', width: size, height: size / 2 + 24, textAlign: 'center' }}>
      <svg width={size} height={size / 2 + 14} viewBox={`0 0 ${size} ${size / 2 + 14}`}>
        <path
          d={`M 14 ${size / 2} A ${r} ${r} 0 0 1 ${size - 14} ${size / 2}`}
          stroke="var(--border)" strokeWidth="10" fill="none" strokeLinecap="round"
        />
        <path
          d={`M 14 ${size / 2} A ${r} ${r} 0 0 1 ${size - 14} ${size / 2}`}
          stroke={color} strokeWidth="10" fill="none" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={off}
          style={{ transition: 'stroke-dashoffset .35s ease, stroke .35s' }}
        />
      </svg>
      <div style={{ position: 'absolute', left: 0, right: 0, top: size / 2 - 32, fontSize: 38,
        fontWeight: 600, letterSpacing: '-0.04em', fontFamily: 'JetBrains Mono, monospace' }}
        className="tnum">
        {Math.round(score)}
      </div>
      <div className="upper" style={{ color, marginTop: 6 }}>{verdict}</div>
    </div>
  );
}

// ── Legend chips ────────────────────────────────────────────────────────────
function SegmentLegend({ compact = false }) {
  const items = [
    { type: 'static', label: 'Static · identity anchor', desc: 'HMAC(secret, "static:id"). Never rotates.' },
    { type: 'totp',   label: 'TOTP · time-rotating',     desc: 'Rotates every 30–120s. T = ⌊now / window⌋.' },
    { type: 'hotp',   label: 'HOTP · counter-rotating',  desc: 'One-shot. Counter advances per use.' },
    { type: 'checksum', label: 'Checksum · tamper guard',desc: 'HMAC over body. Rejects 1−2⁻⁷² of forgeries.' },
  ];
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {items.map((it) => (
        <div key={it.type} className="chip" title={it.desc}>
          <span className={`sw ${it.type}`} />
          {compact ? it.type.toUpperCase() : it.label}
        </div>
      ))}
    </div>
  );
}

// ── small helpers ───────────────────────────────────────────────────────────
function Stat({ label, value, sub, accent }) {
  return (
    <div className="card" style={{ padding: 16 }}>
      <div className="upper" style={{ marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 600, letterSpacing: '-0.02em', color: accent || 'var(--text)' }}
        className="tnum mono">
        {value}
      </div>
      {sub && <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function Pill({ children, tone = 'default', style }) {
  const toneMap = {
    default: { bg: 'var(--surface-2)', fg: 'var(--muted)', bd: 'var(--border)' },
    success: { bg: 'color-mix(in oklab, var(--success) 14%, transparent)', fg: 'var(--success)', bd: 'color-mix(in oklab, var(--success) 28%, transparent)' },
    warn:    { bg: 'color-mix(in oklab, var(--warning) 14%, transparent)', fg: 'var(--warning)', bd: 'color-mix(in oklab, var(--warning) 28%, transparent)' },
    danger:  { bg: 'color-mix(in oklab, var(--danger) 14%, transparent)',  fg: 'var(--danger)',  bd: 'color-mix(in oklab, var(--danger) 28%, transparent)' },
    primary: { bg: 'var(--primary-soft)', fg: 'var(--primary)', bd: 'color-mix(in oklab, var(--primary) 28%, transparent)' },
  };
  const t = toneMap[tone] || toneMap.default;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: '3px 9px', borderRadius: 99, fontSize: 11, fontWeight: 500,
      background: t.bg, color: t.fg, border: `1px solid ${t.bd}`,
      ...style,
    }}>{children}</span>
  );
}

// Tiny clock — wall-clock, ticks 1 Hz
function useClock(intervalMs = 1000) {
  const [t, setT] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setT(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return t;
}

// fast tick for animation
function useTick(intervalMs = 100) {
  const [t, setT] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setT((x) => x + 1), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return t;
}

// Section header
function SectionHead({ eyebrow, title, sub, right }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between',
      marginBottom: 16, gap: 16 }}>
      <div>
        {eyebrow && <div className="upper" style={{ color: 'var(--primary)', marginBottom: 8 }}>{eyebrow}</div>}
        <h2 style={{ marginBottom: 4 }}>{title}</h2>
        {sub && <p style={{ maxWidth: 720 }}>{sub}</p>}
      </div>
      {right}
    </div>
  );
}

Object.assign(window, {
  Logo, KeyGlyph, Ring, Sparkline, ThreatGauge, SegmentLegend,
  Stat, Pill, useClock, useTick, SectionHead,
});
