// screen-provision.jsx — Provisioning Console: real server call, animated pipeline

function ScreenProvision() {
  const [keyLength, setKeyLength] = useState(52);
  const [rotatingCount, setRotatingCount] = useState(3);
  const [map, setMap] = useState(window.DEMO_MAP);
  const [stage, setStage] = useState('ready');  // ready | rolling | done | error
  const [step, setStep] = useState(0);
  const [error, setError] = useState(null);

  // Regenerate key whenever map changes for sample display
  const [sample, setSample] = useState(null);
  useEffect(() => {
    if (!map) return;
    generateKey(map, Date.now()).then(setSample);
  }, [map?.clientId]);

  const payload = map ? provisionPayload(map) : null;

  const steps = [
    'Generating 256-bit shared secret',
    'Allocating client ID',
    'Selecting segment count + types',
    'Jittering segment lengths',
    'Shuffling segment positions',
    'Persisting tumbler map · server-only',
    'Sealing provision payload · positions stripped',
  ];

  const regen = async () => {
    setStage('rolling');
    setStep(0);
    setError(null);

    // Animate steps while the real server call runs
    let i = 0;
    const interval = setInterval(() => {
      i++;
      setStep(i);
      if (i >= steps.length - 1) clearInterval(interval);
    }, 180);

    try {
      const newMap = await provisionFromServer({ keyLength, rotatingCount });
      clearInterval(interval);
      setStep(steps.length);
      setMap(newMap);
      trackEvent('provision_complete', { keyLength, rotatingCount, clientId: newMap.clientId });
      setStage('done');
      setTimeout(() => setStage('ready'), 1500);
    } catch (err) {
      clearInterval(interval);
      setError(err.message);
      setStage('error');
      setTimeout(() => setStage('ready'), 3000);
    }
  };

  return (
    <div className="col" style={{ gap: 24 }}>
      <SectionHead
        eyebrow="Provisioning Console"
        title="Mint a client. Build a tumbler map."
        sub="Real server call: POST /tsk/provision. The server generates the map, stores positions privately, and returns a sealed payload with positions stripped."
        right={
          <button className="btn primary" onClick={regen} disabled={stage === 'rolling'}>
            {stage === 'rolling' ? 'Provisioning…' : 'Provision new client'}
          </button>
        }
      />

      {/* Config + Pipeline */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: 16 }}>
        <div className="card">
          <h3 style={{ marginBottom: 12 }}>Parameters</h3>
          <div className="col" style={{ gap: 14 }}>
            <Param label="Key length" value={keyLength} unit="chars" min={32} max={128} step={4}
              onChange={setKeyLength} hint="Spec default 52. Server enforces ≤ 128 (DoS bound)." />
            <Param label="Rotating segments" value={rotatingCount} min={2} max={5} step={1}
              onChange={setRotatingCount}
              hint="2–5 rotating segments + 1 static + 1 checksum. Each gets a random type and timing." />
            <div>
              <div className="upper" style={{ marginBottom: 6 }}>Auth · Provisioner endpoint</div>
              <div className="mono" style={{ fontSize: 12, color: 'var(--muted)' }}>
                <span style={{ color: 'var(--success)' }}>POST</span> /tsk/provision
              </div>
            </div>
            <div>
              <div className="upper" style={{ marginBottom: 6 }}>Rate</div>
              <div className="mono" style={{ fontSize: 12, color: 'var(--muted)' }}>30 req/min · tenant</div>
            </div>
          </div>
        </div>

        <div className="card flush">
          <div className="ch">
            <h3>Provisioning pipeline</h3>
            <Pill tone={
              stage === 'rolling' ? 'warn' :
              stage === 'done' ? 'success' :
              stage === 'error' ? 'danger' : 'primary'
            }>
              {stage === 'rolling'
                ? <><span className="live-dot" style={{ background: 'var(--warning)', boxShadow: '0 0 10px var(--warning)' }} /> running on server</>
                : stage === 'done' ? '✓ sealed'
                : stage === 'error' ? '✗ failed'
                : 'idle · awaiting trigger'}
            </Pill>
          </div>
          <div className="cb">
            {error && (
              <div style={{ padding: 10, borderRadius: 8, background: 'color-mix(in oklab, var(--danger) 12%, transparent)',
                border: '1px solid color-mix(in oklab, var(--danger) 30%, transparent)',
                color: 'var(--danger)', fontSize: 12, marginBottom: 12 }}>
                {error}
              </div>
            )}
            <div className="col" style={{ gap: 8 }}>
              {steps.map((s, i) => {
                const active = stage === 'rolling' && i === step - 1;
                const done = (stage === 'rolling' && i < step - 1) || stage === 'done';
                return (
                  <div key={i} className="row" style={{ gap: 12, padding: '8px 10px',
                    background: active ? 'color-mix(in oklab, var(--primary) 10%, transparent)' : 'transparent',
                    borderRadius: 6, transition: '.15s' }}>
                    <span className="mono tnum dim" style={{ fontSize: 11, width: 28 }}>
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span style={{
                      width: 14, height: 14, borderRadius: 99, display: 'inline-flex',
                      alignItems: 'center', justifyContent: 'center',
                      background: done ? 'var(--success)' : active ? 'var(--primary)' : 'var(--surface-2)',
                      color: done || active ? '#08111c' : 'var(--dim)', fontSize: 9, fontWeight: 700,
                      boxShadow: active ? '0 0 12px var(--primary)' : 'none',
                    }}>
                      {done ? '✓' : active ? '·' : ''}
                    </span>
                    <span style={{ fontSize: 13, color: done || active ? 'var(--text)' : 'var(--muted)' }}>{s}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Split view: client payload vs server map */}
      {map && payload && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {/* Client payload */}
          <div className="card flush">
            <div className="ch">
              <div>
                <h3>Client receives · provision payload</h3>
                <div className="muted" style={{ fontSize: 11.5, marginTop: 2 }}>
                  Returned by POST /tsk/provision · positions stripped
                </div>
              </div>
              <Pill tone="primary">≤ what client needs</Pill>
            </div>
            <pre className="mono" style={{
              margin: 0, padding: 18, fontSize: 12, lineHeight: 1.55,
              color: 'var(--muted)', background: 'var(--bg-2)',
              borderBottomLeftRadius: 'var(--r-lg)', borderBottomRightRadius: 'var(--r-lg)',
              overflow: 'auto', maxHeight: 360,
            }}>
              {JSON.stringify(payload, null, 2)}
            </pre>
          </div>

          {/* Server map — with the secret positions */}
          <div className="card flush" style={{ position: 'relative', overflow: 'hidden' }}>
            <div style={{
              position: 'absolute', inset: 0,
              background: 'repeating-linear-gradient(135deg, transparent 0 14px, color-mix(in oklab, var(--danger) 5%, transparent) 14px 15px)',
              pointerEvents: 'none', opacity: .6,
            }} />
            <div className="ch" style={{ position: 'relative' }}>
              <div>
                <h3>Server stores · tumbler map</h3>
                <div className="muted" style={{ fontSize: 11.5, marginTop: 2 }}>
                  Confidential · never transmitted after provisioning
                </div>
              </div>
              <Pill tone="danger">SERVER ONLY</Pill>
            </div>
            <pre className="mono" style={{
              margin: 0, padding: 18, fontSize: 12, lineHeight: 1.55,
              color: 'var(--muted)', background: 'var(--bg-2)', position: 'relative',
              borderBottomLeftRadius: 'var(--r-lg)', borderBottomRightRadius: 'var(--r-lg)',
              overflow: 'auto', maxHeight: 360,
            }}>
              {JSON.stringify({
                clientId: map.clientId,
                sharedSecret: map.sharedSecret.slice(0, 8) + '…' + map.sharedSecret.slice(-4),
                keyLength: map.keyLength,
                segments: map.segments.map(s => ({
                  id: s.id,
                  type: s.type,
                  position: s.position,
                  length: s.length,
                  ...(s.windowSec ? { windowSec: s.windowSec } : {}),
                  ...(s.counter !== null && s.counter !== undefined ? { counter: s.counter } : {}),
                })),
                createdAt: map.createdAt,
              }, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* Sample assembled key */}
      {map && sample && (
        <div className="card">
          <div className="row" style={{ justifyContent: 'space-between', marginBottom: 14 }}>
            <div>
              <h3>Sample assembled key · this client</h3>
              <p style={{ fontSize: 12.5, marginTop: 4 }}>
                Generated with real HMAC-SHA256 (Web Crypto API). Server assembles by position; client concatenates in provisioned order.
              </p>
            </div>
            <span className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>{map.keyLength} chars</span>
          </div>
          <KeyGlyph map={map} parts={sample.parts} view="server" />
          <div className="divider" />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <Stat label="Total segments" value={map.segments.length} sub="incl. static + checksum" />
            <Stat label="TOTP segments" value={map.segments.filter(s => s.type === 'totp').length}
              sub="time-rotating" accent="var(--totp)" />
            <Stat label="HOTP segments" value={map.segments.filter(s => s.type === 'hotp').length}
              sub="counter-rotating" accent="var(--hotp)" />
            <Stat label="Key length" value={map.keyLength}
              sub="chars total" accent="var(--primary)" />
          </div>
        </div>
      )}
    </div>
  );
}

function Param({ label, value, unit, min, max, step, onChange, hint }) {
  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
        <span className="upper">{label}</span>
        <span className="mono tnum" style={{ fontSize: 13, fontWeight: 600 }}>
          {value}{unit ? ` ${unit}` : ''}
        </span>
      </div>
      <input type="range" min={min} max={max} step={step} value={value}
        onChange={e => onChange(parseInt(e.target.value))}
        style={{ width: '100%', accentColor: 'var(--primary)', height: 4 }} />
      {hint && <div className="muted" style={{ fontSize: 11.5, marginTop: 6, lineHeight: 1.4 }}>{hint}</div>}
    </div>
  );
}

window.ScreenProvision = ScreenProvision;
