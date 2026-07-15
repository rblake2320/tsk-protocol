// screen-vault.jsx — Live key visualizer with real HMAC-SHA256 via useGenerateKey

function ScreenVault() {
  const [map, setMap] = useState(window.DEMO_MAP);
  useEffect(() => {
    const handler = e => setMap(e.detail);
    window.addEventListener('demo-map-updated', handler);
    return () => window.removeEventListener('demo-map-updated', handler);
  }, []);
  const [counters, setCounters] = useState({});
  const [view, setView] = useState('server');
  const [paused, setPaused] = useState(false);
  const pausedAtRef = useRef(null);
  const tick = useTick(paused ? 99999 : 120);
  const now = paused
    ? (pausedAtRef.current || Date.now())
    : Date.now();

  // Capture pause timestamp so frozen key stays stable
  useEffect(() => {
    if (paused && !pausedAtRef.current) pausedAtRef.current = Date.now();
    if (!paused) pausedAtRef.current = null;
  }, [paused]);

  const gen = useGenerateKey(map, now, counters);

  // Segment flash + rotation history
  const prevRef = useRef({});
  const historyRef = useRef({});
  const flashing = {};
  if (gen) {
    for (const id in gen.parts) {
      if (prevRef.current[id] && prevRef.current[id] !== gen.parts[id]) {
        flashing[id] = true;
        historyRef.current[id] = [gen.parts[id], ...(historyRef.current[id] || [])].slice(0, 4);
      }
    }
  }
  useEffect(() => { if (gen) prevRef.current = gen.parts; }, [gen?.key]);

  const advanceHotp = segId => setCounters(c => ({ ...c, [segId]: (c[segId] ?? 0) + 1 }));

  // Expiry countdown — must be declared before any conditional return (Rules of Hooks)
  const [expiryLabel, setExpiryLabel] = useState('');
  useEffect(() => {
    if (!map?.expiresAt) { setExpiryLabel('Never'); return; }
    const update = () => {
      const remaining = map.expiresAt - Date.now();
      if (remaining <= 0) { setExpiryLabel('Expired'); return; }
      const days = Math.floor(remaining / 86400000);
      const hours = Math.floor((remaining % 86400000) / 3600000);
      const mins = Math.floor((remaining % 3600000) / 60000);
      setExpiryLabel(days > 0 ? `${days}d ${hours}h remaining` : hours > 0 ? `${hours}h ${mins}m remaining` : `${mins}m remaining`);
    };
    update();
    const iv = setInterval(update, 1000);
    return () => clearInterval(iv);
  }, [map?.expiresAt]);

  if (!map || !gen) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '40vh' }}>
        <span className="muted">Computing key…</span>
      </div>
    );
  }

  return (
    <div className="col" style={{ gap: 24 }}>
      <SectionHead
        eyebrow="Live Vault · port 3200"
        title="Watch a key tumble."
        sub="The same key string from three perspectives. The client also retains ordered metadata and the shared secret outside this simplified wire view."
        right={
          <div className="row" style={{ gap: 8 }}>
            <Pill tone={paused ? 'warn' : 'success'}>
              {paused ? '⏸ paused' : <><span className="live-dot" /> tumbling</>}
            </Pill>
            <button className="btn sm" onClick={() => setPaused(p => !p)}>
              {paused ? 'Resume' : 'Pause'}
            </button>
          </div>
        }
      />

      {/* Credential status */}
      <div className="card">
        <h3 style={{ marginBottom: 12 }}>Credential status</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          <Stat label="Status" value={map.status ?? 'active'}
            sub={(map.status ?? 'active') === 'expired' ? 'not accepted' : 'accepted'}
            accent={(map.status ?? 'active') === 'expired' ? 'var(--danger)' : 'var(--success)'} />
          <Stat label="Expires" value={expiryLabel}
            sub={map.expiresAt ? new Date(map.expiresAt).toLocaleString() : 'no expiry set'}
            accent={map.expiresAt && Date.now() > map.expiresAt ? 'var(--danger)' : 'var(--success)'} />
          <Stat label="Requests" value={map.maxRequests ? `${map.requestCount ?? 0} / ${map.maxRequests}` : `${map.requestCount ?? 0}`}
            sub={map.maxRequests ? `${Math.round(100 - ((map.requestCount ?? 0) / map.maxRequests * 100))}% remaining` : 'unlimited'}
            accent="var(--primary)" />
          <Stat label="Label" value={map.label || '(none)'}
            sub={map.lastUsedAt ? `last used ${new Date(map.lastUsedAt).toLocaleTimeString()}` : 'never used'}
            accent="var(--muted)" />
        </div>
      </div>

      {/* View switcher */}
      <div className="card flush">
        <div className="ch">
          <div className="row" style={{ gap: 4 }}>
            {[
              { id: 'server',   label: 'Server view',   desc: 'Sees positions + types' },
              { id: 'client',   label: 'Client view',   desc: 'Sees assembled string only' },
              { id: 'attacker', label: 'Attacker view', desc: 'Has the wire payload — nothing else' },
            ].map(v => (
              <button key={v.id} onClick={() => setView(v.id)}
                className="btn sm"
                style={{
                  background: view === v.id ? 'var(--primary-soft)' : 'transparent',
                  color: view === v.id ? 'var(--primary)' : 'var(--muted)',
                  borderColor: view === v.id ? 'color-mix(in oklab, var(--primary) 30%, transparent)' : 'transparent',
                }}>
                {v.label}
              </button>
            ))}
          </div>
          <div className="row" style={{ gap: 8 }}>
            <span className="muted" style={{ fontSize: 12 }}>Client ID</span>
            <span className="mono" style={{ fontSize: 12, color: 'var(--text)' }}>{map.clientId}</span>
          </div>
        </div>

        <div className="cb" style={{ paddingTop: 28 }}>
          {view === 'server' && <KeyGlyph map={map} parts={gen.parts} view="server" flashing={flashing} />}
          {view === 'client' && <KeyGlyph map={map} parts={gen.parts} view="client" />}
          {view === 'attacker' && <KeyGlyph map={map} parts={gen.parts} view="attacker" />}

          {view === 'server' && <div style={{ marginTop: 24 }}><SegmentLegend /></div>}
          {view === 'client' && (
            <div className="muted" style={{ marginTop: 18, fontSize: 13, maxWidth: 680 }}>
              The SDK assembles segments locally from ordered metadata. The lengths reveal cumulative
              boundaries; layout is not treated as a secret authentication factor.
            </div>
          )}
          {view === 'attacker' && (
            <div className="muted" style={{ marginTop: 18, fontSize: 13, maxWidth: 680 }}>
              The wire key has no boundary markers. A previously accepted generated key is denied by atomic
              counter consumption; an intercepted unused credential can still be raced and must be protected by TLS.
            </div>
          )}
        </div>
      </div>

      {/* Segment inspector + time epochs */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 16 }}>
        <div className="card flush">
          <div className="ch">
            <h3>Segment inspector</h3>
            <div className="row" style={{ gap: 10 }}>
              <span className="muted" style={{ fontSize: 12 }}>Real HMAC-SHA256</span>
              <Pill tone="primary">Web Crypto API</Pill>
            </div>
          </div>
          <table>
            <thead>
              <tr>
                <th>Segment ID</th>
                <th>Type</th>
                <th>Pos · Len</th>
                <th>Rotation</th>
                <th>Current value</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {map.segments.map(s => {
                const tr = gen.trace[s.id];
                const isTotp = s.type === 'totp';
                const isHotp = s.type === 'hotp';
                return (
                  <tr key={s.id}>
                    <td className="mono" style={{ fontSize: 12 }}>{s.id}</td>
                    <td>
                      <span className="chip">
                        <span className={`sw ${s.type}`} />{s.type}
                      </span>
                    </td>
                    <td className="mono tnum" style={{ fontSize: 12 }}>
                      [{s.position[0]}, {s.position[1]}) · {s.length}
                    </td>
                    <td className="muted" style={{ fontSize: 12 }}>
                      {s.type === 'static' && 'never'}
                      {isTotp && <>every {s.windowSec}s · T={tr?.label?.replace('T=', '')}</>}
                      {isHotp && <>per use · c={tr?.label?.replace('c=', '')}</>}
                      {s.type === 'checksum' && 'derived'}
                    </td>
                    <td>
                      <span className={`mono ${flashing[s.id] ? 'seg flash' : ''}`}
                        style={{
                          fontSize: 12, padding: '3px 6px', borderRadius: 4,
                          background: s.type === 'static' ? 'color-mix(in oklab, var(--static) 16%, transparent)'
                                    : s.type === 'totp' ? 'color-mix(in oklab, var(--totp) 16%, transparent)'
                                    : s.type === 'hotp' ? 'color-mix(in oklab, var(--hotp) 16%, transparent)'
                                    : 'var(--surface-2)',
                          color: s.type === 'static' ? 'var(--static)'
                              : s.type === 'totp' ? 'var(--totp)'
                              : s.type === 'hotp' ? 'var(--hotp)' : 'var(--muted)',
                        }}>
                        {gen.parts[s.id]}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {isHotp && (
                        <button className="btn sm" onClick={() => advanceHotp(s.id)}>
                          Use ↻
                        </button>
                      )}
                      {isTotp && tr && (
                        <Ring progress={1 - (tr.elapsedMs / (s.windowSec * 1000))}
                          size={22} stroke={2} color={`var(--${s.type})`} />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Right: time epochs + rotation history */}
        <div className="col" style={{ gap: 16 }}>
          <div className="card">
            <div className="row" style={{ justifyContent: 'space-between', marginBottom: 10 }}>
              <h3>Time epochs</h3>
              <Pill tone="primary">T = ⌊now / windowSec⌋</Pill>
            </div>
            <div className="col" style={{ gap: 8 }}>
              {map.segments.filter(s => s.type === 'totp').map(s => {
                const tr = gen.trace[s.id];
                if (!tr) return null;
                const prog = tr.elapsedMs / (s.windowSec * 1000);
                return (
                  <div key={s.id}>
                    <div className="row" style={{ justifyContent: 'space-between', marginBottom: 4 }}>
                      <span className="mono" style={{ fontSize: 11 }}>{s.id}</span>
                      <span className="mono tnum" style={{ fontSize: 11, color: 'var(--muted)' }}>
                        T={tr.T} · {(s.windowSec - tr.elapsedMs / 1000).toFixed(1)}s left
                      </span>
                    </div>
                    <div style={{ height: 4, background: 'var(--border)', borderRadius: 99 }}>
                      <div style={{
                        height: '100%', width: `${(1 - prog) * 100}%`,
                        background: 'var(--totp)', borderRadius: 99, transition: 'width .15s linear',
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="card">
            <h3 style={{ marginBottom: 10 }}>Rotation history</h3>
            <div className="col" style={{ gap: 8 }}>
              {map.segments.filter(s => s.type === 'totp' || s.type === 'hotp').map(s => (
                <div key={s.id}>
                  <div className="upper" style={{ marginBottom: 4, color: `var(--${s.type})` }}>{s.id}</div>
                  <div className="row" style={{ gap: 4, fontSize: 11, flexWrap: 'wrap' }}>
                    <span className="mono" style={{
                      padding: '3px 6px', borderRadius: 4,
                      background: `color-mix(in oklab, var(--${s.type}) 18%, transparent)`,
                      color: `var(--${s.type})`, fontWeight: 600,
                    }}>{gen.parts[s.id]}</span>
                    {(historyRef.current[s.id] || []).slice(0, 3).map((v, i) => (
                      <span key={i} className="mono" style={{
                        padding: '3px 6px', borderRadius: 4, background: 'var(--surface-2)',
                        color: 'var(--dim)', textDecoration: 'line-through', opacity: 0.7 - i * 0.2,
                      }}>{v}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* HMAC derivation panel */}
      <div className="card flush">
        <div className="ch">
          <h3>HMAC derivation · this tick</h3>
          <Pill>HMAC-SHA256 · base64url · Web Crypto API</Pill>
        </div>
        <div className="cb">
          <div className="mono" style={{ fontSize: 12, lineHeight: 1.9, color: 'var(--muted)' }}>
            {map.segments.filter(s => s.type !== 'checksum').map(s => {
              const tr = gen.trace[s.id];
              if (!tr) return null;
              const lbl = s.type === 'static' ? `"static:${s.id}"`
                        : s.type === 'totp'   ? `"totp:${s.id}:${tr.T}"`
                        :                       `"hotp:${s.id}:${tr.T}"`;
              return (
                <div key={s.id}>
                  <span style={{ color: 'var(--dim)' }}>HMAC(secret, </span>
                  <span style={{ color: `var(--${s.type})` }}>{lbl}</span>
                  <span style={{ color: 'var(--dim)' }}>) → </span>
                  <span style={{ color: 'var(--text)' }}>{gen.parts[s.id]}</span>
                </div>
              );
            })}
            <div>
              <span style={{ color: 'var(--dim)' }}>HMAC(secret, </span>
              <span style={{ color: 'var(--checksum)' }}>"checksum:" + body</span>
              <span style={{ color: 'var(--dim)' }}>) → </span>
              <span style={{ color: 'var(--text)' }}>{gen.parts['seg_checksum']}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

window.ScreenVault = ScreenVault;
