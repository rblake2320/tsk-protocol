// screen-overview.jsx — Landing / hero with live tumbling key (real HMAC)

function ScreenOverview({ goto }) {
  const map = window.DEMO_MAP;
  const [counters] = useState({});
  const tick = useTick(120);
  const now = Date.now();

  const gen = useGenerateKey(map, now, counters);

  // Flash segments when their value changes
  const prevRef = useRef({});
  const flashing = {};
  if (gen) {
    for (const id in gen.parts) {
      if (prevRef.current[id] && prevRef.current[id] !== gen.parts[id]) flashing[id] = true;
    }
  }
  useEffect(() => { if (gen) prevRef.current = gen.parts; }, [gen?.key]);

  if (!map || !gen) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '40vh' }}>
        <span className="muted">Generating key…</span>
      </div>
    );
  }

  return (
    <div className="col" style={{ gap: 36 }}>
      {/* ── HERO ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.05fr 1fr', gap: 32, alignItems: 'center', marginTop: 8 }}>
        <div>
          <Pill tone="primary">
            <span className="live-dot" style={{ background: 'var(--primary)', boxShadow: '0 0 10px var(--primary)' }} />
            Patent-pending · v1.1
          </Pill>
          <h1 style={{ marginTop: 18 }}>
            API keys that <span style={{
              background: 'linear-gradient(120deg, var(--totp), var(--primary))',
              WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent',
            }}>rotate inside themselves</span>.
          </h1>
          <p style={{ marginTop: 16, fontSize: 17, maxWidth: 560, color: 'var(--muted)', lineHeight: 1.5 }}>
            TSK is a tumbler-style authentication protocol. Each key is a string whose
            <span style={{ color: 'var(--text)' }}> internal segments rotate independently</span>,
            and whose <span style={{ color: 'var(--text)' }}>positional map is a per-client server secret</span>.
            Captured keys are structurally useless after the shortest rotation window.
          </p>
          <div className="row" style={{ marginTop: 24, gap: 10 }}>
            <button className="btn primary" onClick={() => goto('vault')}>
              See it tumble →
            </button>
            <button className="btn" onClick={() => goto('stack')}>
              The 8-layer stack
            </button>
            <span className="muted" style={{ fontSize: 12, marginLeft: 10 }}>
              <span className="kbd">G</span> <span className="kbd">V</span> · jump to vault
            </span>
          </div>
          <div className="row" style={{ marginTop: 32, gap: 22 }}>
            <div>
              <div className="upper">Replay window</div>
              <div className="tnum mono" style={{ fontSize: 22, fontWeight: 600 }}>≤ 30s</div>
            </div>
            <div style={{ width: 1, height: 36, background: 'var(--border)' }} />
            <div>
              <div className="upper">Position entropy</div>
              <div className="tnum mono" style={{ fontSize: 22, fontWeight: 600 }}>2<sup style={{ fontSize: 13 }}>122</sup></div>
            </div>
            <div style={{ width: 1, height: 36, background: 'var(--border)' }} />
            <div>
              <div className="upper">Stack layers</div>
              <div className="tnum mono" style={{ fontSize: 22, fontWeight: 600 }}>8</div>
            </div>
          </div>
        </div>

        {/* Live key card */}
        <div className="card" style={{ position: 'relative', overflow: 'hidden' }}>
          <div style={{
            position: 'absolute', inset: 0, pointerEvents: 'none', opacity: .6,
            background: 'radial-gradient(420px 200px at 80% -20%, var(--primary-soft), transparent 70%)',
          }} />
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div className="row" style={{ gap: 10 }}>
              <span className="live-dot" />
              <span className="upper">Live key · server view</span>
            </div>
            <Pill tone="success">tumbling</Pill>
          </div>

          <KeyGlyph map={map} parts={gen.parts} view="server" flashing={flashing} />

          <div className="divider" />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
            {map.segments.filter(s => s.type !== 'checksum').map(s => {
              const tr = gen.trace[s.id];
              const isTotp = s.type === 'totp';
              const prog = isTotp ? (tr.elapsedMs / (s.windowSec * 1000)) : 0;
              return (
                <div key={s.id} style={{
                  padding: 10, borderRadius: 8, border: '1px solid var(--border)',
                  background: 'var(--bg-2)', display: 'flex', alignItems: 'center', gap: 10,
                }}>
                  {isTotp ? (
                    <Ring progress={1 - prog} size={28} stroke={2.5} color={`var(--${s.type})`} />
                  ) : (
                    <span className={`sw ${s.type}`} style={{ width: 12, height: 12, borderRadius: 99 }} />
                  )}
                  <div style={{ minWidth: 0 }}>
                    <div className="upper" style={{ color: `var(--${s.type})` }}>{s.label}</div>
                    <div className="mono tnum" style={{ fontSize: 11, color: 'var(--muted)' }}>
                      {isTotp ? `${(s.windowSec - tr.elapsedMs / 1000).toFixed(1)}s` : tr.label}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="divider" />
          <SegmentLegend compact />
        </div>
      </div>

      {/* ── PROBLEM / SOLUTION ── */}
      <div className="g3">
        {[
          { eyebrow: '01', title: 'Static keys leak. Forever.', body: 'A key in a logfile, env var, or build artifact is a live credential until manually revoked. Industry mean-time-to-rotation: weeks.' },
          { eyebrow: '02', title: 'Rotation alone is not enough.', body: 'AWS Secrets Manager and Vault swap the whole string on a schedule. Within the window, the key is still static — and replayable.' },
          { eyebrow: '03', title: 'TSK makes the shape secret.', body: 'Not just the value — the structure. Attackers cannot tell which characters rotate, at what rate, or where they live in the string.' },
        ].map(b => (
          <div className="card" key={b.eyebrow}>
            <div className="upper" style={{ color: 'var(--primary)' }}>{b.eyebrow}</div>
            <h3 style={{ marginTop: 8, marginBottom: 8, fontSize: 17, letterSpacing: '-0.015em' }}>{b.title}</h3>
            <p style={{ fontSize: 13 }}>{b.body}</p>
          </div>
        ))}
      </div>

      {/* ── FEATURE MATRIX ── */}
      <div>
        <SectionHead
          eyebrow="Capabilities"
          title="Built for the keys you can't afford to lose."
          sub="Every property below is enforced at the protocol level — not as a deployment best practice."
        />
        <div className="g4">
          {[
            ['Structural secrecy', 'Segment positions, lengths, and ordering are stored server-side only. The provision payload omits all of them.'],
            ['Independent rotation', 'TOTP segments expire at 30–120s. HOTP segments are one-shot. Static segment anchors identity.'],
            ['Atomic CAS replay block', 'HOTP counter advances via compare-and-swap. Concurrent replay of the same key is blocked by the store.'],
            ['Checksum-first validation', '72-bit HMAC checksum rejects 1 − 2⁻⁷² of forgeries before any segment is touched. DoS-resistant by construction.'],
            ['Per-segment anomaly intel', 'Static-passes-rotating-fails is the stolen-key fingerprint. The engine reads it directly.'],
            ['BPC composability', 'Stack TSK behind device-bound ECDSA. Two orthogonal factors, one bridge.'],
            ['Brute-force margin', 'C(L − Σℓ + N, N) positional arrangements × segment HMAC entropy. Astronomical even for short keys.'],
            ['Wire compatible', 'Three headers. No new handshake. Drop into any HTTPS stack.'],
          ].map(([h, b]) => (
            <div className="card" key={h} style={{ padding: 18 }}>
              <h3 style={{ fontSize: 14, letterSpacing: '-0.01em', marginBottom: 8 }}>{h}</h3>
              <p style={{ fontSize: 12.5 }}>{b}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── CTA ── */}
      <div className="card" style={{
        background: 'linear-gradient(135deg, var(--primary-soft), transparent 70%), var(--surface)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 24, flexWrap: 'wrap',
      }}>
        <div>
          <h2 style={{ fontSize: 22 }}>Inspect every screen of the protocol.</h2>
          <p style={{ marginTop: 6 }}>Live vault · attack lab · provisioning console · 8-layer stack.</p>
        </div>
        <div className="row" style={{ gap: 10 }}>
          <button className="btn primary" onClick={() => goto('vault')}>Live Vault</button>
          <button className="btn" onClick={() => goto('attack')}>Attack Lab</button>
          <button className="btn" onClick={() => goto('provision')}>Provision</button>
          <button className="btn" onClick={() => goto('stack')}>The Stack</button>
        </div>
      </div>
    </div>
  );
}

window.ScreenOverview = ScreenOverview;
