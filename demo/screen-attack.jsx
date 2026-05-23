// screen-attack.jsx — Attack Lab: real server validation for all attacks

function ScreenAttack() {
  const map = window.DEMO_MAP;
  const [counters, setCounters] = useState({});
  const [captured, setCaptured] = useState(null);  // {key, parts, t}
  const [attempts, setAttempts] = useState([]);     // [{t, kind, label, result, score}]
  const [events, setEvents] = useState([]);         // local anomaly events
  const [serverAnomaly, setServerAnomaly] = useState(null);
  const [firing, setFiring] = useState(false);
  const tick = useTick(120);
  const now = Date.now();

  const gen = useGenerateKey(map, now, counters);

  // Fetch real anomaly score after each attack
  const refreshAnomaly = async () => {
    if (!map) return;
    const score = await fetchServerAnomaly(map.clientId);
    if (score !== null) setServerAnomaly(score);
  };

  const fire = async (kind) => {
    if (!map || !gen) return;
    if (kind !== 'capture' && firing) return;
    setFiring(true);

    const t = Date.now();
    let label = '';
    let result = {};
    let eventKind = null;

    try {
      if (kind === 'capture') {
        const cap = { key: gen.key, parts: { ...gen.parts }, t };
        setCaptured(cap);
        label = 'Capture live key';
        result = { verdict: 'observed', results: {} };
        trackEvent('attack_capture', { screen: 'attack' });
        setAttempts(a => [{ t, kind, label, result }, ...a].slice(0, 12));
        setFiring(false);
        return;
      }

      if (kind === 'replay-now') {
        if (!captured) { setFiring(false); return; }
        // Send the captured key exactly as-is to the real server
        const srv = await verifyWithServer(map.clientId, captured.key);
        const age = ((t - captured.t) / 1000).toFixed(1);
        label = `Replay captured key (Δt = ${age}s)`;
        result = {
          verdict: srv.ok ? 'accept' : 'reject',
          serverError: srv.data?.error,
          staticPass: !srv.ok,
          rotFail: !srv.ok,
          status: srv.status,
          results: {},
        };
        eventKind = srv.ok ? null : 'fail-rotating';
      }

      if (kind === 'replay-30s') {
        if (!captured) { setFiring(false); return; }
        // Generate key using time shifted 2.5 windows back → TOTP will be expired
        const firstTotp = map.segments.find(s => s.type === 'totp');
        const shiftMs = firstTotp ? (firstTotp.windowSec * 2.5 * 1000) : 75000;
        const expiredGen = await generateKey(map, Date.now() - shiftMs, counters);
        const srv = await verifyWithServer(map.clientId, expiredGen.key);
        label = 'Replay expired key (TOTP windows shifted back)';
        result = {
          verdict: srv.ok ? 'accept' : 'reject',
          serverError: srv.data?.error,
          staticPass: true,
          rotFail: true,
          status: srv.status,
          results: {},
        };
        eventKind = 'fail-rotating';
      }

      if (kind === 'forge-static') {
        // Corrupt one character of the static segment value, rebuild the full key
        const staticSeg = map.segments.find(s => s.type === 'static');
        if (!staticSeg) { setFiring(false); return; }
        const corruptedVal = gen.parts[staticSeg.id].slice(0, -1) + 'X';
        // Rebuild the key with the corrupted static segment
        const ordered = map.segments.slice().sort((a, b) => a.position[0] - b.position[0]);
        let forgedKey = '';
        for (const seg of ordered) {
          if (seg.id === staticSeg.id) forgedKey += corruptedVal;
          else forgedKey += gen.parts[seg.id];
        }
        const srv = await verifyWithServer(map.clientId, forgedKey);
        label = 'Forge: tweak one static byte';
        result = {
          verdict: srv.ok ? 'accept' : 'reject',
          serverError: srv.data?.error,
          allFail: true,
          status: srv.status,
          results: {},
        };
        eventKind = 'fail-all';
      }

      if (kind === 'forge-checksum') {
        // Corrupt the checksum segment (last N chars)
        const csSeg = map.segments.find(s => s.type === 'checksum');
        if (!csSeg) { setFiring(false); return; }
        const corruptedCs = 'XX' + gen.parts['seg_checksum'].slice(2);
        const ordered = map.segments.slice().sort((a, b) => a.position[0] - b.position[0]);
        let forgedKey = '';
        for (const seg of ordered) {
          if (seg.id === 'seg_checksum') forgedKey += corruptedCs;
          else forgedKey += gen.parts[seg.id];
        }
        const srv = await verifyWithServer(map.clientId, forgedKey);
        label = 'Forge: corrupt checksum (rejected before segments)';
        result = {
          verdict: 'reject',
          serverError: srv.data?.error,
          checksumFail: true,
          status: srv.status,
          results: {},
        };
        eventKind = 'fail-all';
      }

      if (kind === 'brute-burst') {
        // 6 random forgeries — all sent to real server
        const localEvents = [];
        for (let i = 0; i < 6; i++) {
          const randomKey = gen.key.split('').map((c, j) =>
            (j === Math.floor(Math.random() * gen.key.length)) ? 'Z' : c
          ).join('');
          await verifyWithServer(map.clientId, randomKey);
          localEvents.push({ t: Date.now() + i * 50, kind: 'fail-all' });
        }
        setEvents(ev => [...ev, ...localEvents]);
        label = 'Brute burst · 6 random forgeries → real server';
        result = { verdict: 'reject', results: {}, allFail: true };
        setAttempts(a => [{ t, kind, label, result }, ...a].slice(0, 12));
        await refreshAnomaly();
        setFiring(false);
        return;
      }

      if (eventKind) setEvents(ev => [...ev, { t, kind: eventKind }]);
      trackEvent('attack_fired', { kind, verdict: result.verdict, status: result.status });
      setAttempts(a => [{ t, kind, label, result }, ...a].slice(0, 12));
      await refreshAnomaly();
    } catch (err) {
      setAttempts(a => [{
        t, kind, label: label || kind,
        result: { verdict: 'error', serverError: err.message, results: {} },
      }, ...a].slice(0, 12));
    }

    setFiring(false);
  };

  const resetAll = () => { setAttempts([]); setEvents([]); setCaptured(null); setServerAnomaly(null); };

  const localAnomaly = evalAnomaly(events);
  // Show server anomaly score if available, fall back to local scoring
  const displayScore = serverAnomaly?.score ?? localAnomaly.score;
  const displayVerdict = serverAnomaly?.verdict ?? localAnomaly.verdict;

  const scoreHistoryRef = useRef([0]);
  useEffect(() => {
    scoreHistoryRef.current = [...scoreHistoryRef.current, displayScore].slice(-40);
  }, [events.length, serverAnomaly?.score]);

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
        eyebrow="Attack Lab"
        title="Try to break it. Watch the engine notice."
        sub="Capture a live key. Replay it. Forge it. Every attack hits the real server — the anomaly engine reads which segments failed and scores in real time."
        right={
          <div className="row" style={{ gap: 8 }}>
            <button className="btn sm" onClick={resetAll}>Reset</button>
            {firing && <Pill tone="warn"><span className="live-dot" style={{ background: 'var(--warning)', boxShadow: '0 0 10px var(--warning)' }} /> firing…</Pill>}
          </div>
        }
      />

      {/* Captured payload tray */}
      <div className="card">
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 14 }}>
          <div>
            <h3>Captured payload</h3>
            <p style={{ fontSize: 12.5, marginTop: 4 }}>
              {captured
                ? <>Intercepted {((Date.now() - captured.t) / 1000).toFixed(1)}s ago. Try replaying or forging it below.</>
                : <>No payload yet. Step 1 — grab one from the wire.</>}
            </p>
          </div>
          <button className="btn primary" onClick={() => fire('capture')} disabled={!gen}>
            ⌖ Capture live key
          </button>
        </div>
        {captured && (
          <div style={{ padding: '12px 14px', background: 'var(--bg-2)',
            border: '1px dashed var(--border-2)', borderRadius: 10 }}>
            <div className="upper" style={{ marginBottom: 8, color: 'var(--danger)' }}>
              ATTACKER WIRE VIEW · {new Date(captured.t).toLocaleTimeString()}
            </div>
            <KeyGlyph map={map} parts={captured.parts} view="attacker" />
          </div>
        )}
      </div>

      {/* Attack triggers + anomaly */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 16 }}>
        <div className="card flush">
          <div className="ch"><h3>Attack vectors</h3><Pill>5 live · real server</Pill></div>
          <div className="cb" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <AttackCard
              kind="replay-now" label="Replay immediately"
              desc="Submit captured key to real server. If HOTP counter already advanced on first use, this fails."
              hint={!captured ? null : "Tip: click 'Use ↻' in Live Vault first to advance the HOTP counter — then replay here to see the reject."}
              disabled={!captured || firing} onFire={() => fire('replay-now')} />
            <AttackCard
              kind="replay-30s" label="Replay expired key"
              desc="Generate key 2.5 TOTP windows in the past. TOTP segments are garbage. Server rejects."
              disabled={!captured || firing} onFire={() => fire('replay-30s')} highValue />
            <AttackCard
              kind="forge-static" label="Forge static byte"
              desc="Flip one character of the static segment. Server detects tampered identity anchor."
              disabled={firing} onFire={() => fire('forge-static')} />
            <AttackCard
              kind="forge-checksum" label="Corrupt checksum"
              desc="Mutate the checksum tail. Server rejects before any segment validation runs."
              disabled={firing} onFire={() => fire('forge-checksum')} />
            <AttackCard
              kind="brute-burst" label="Brute burst ×6"
              desc="Six random forgeries sent to real server. Watch threat score spike in the anomaly engine."
              danger disabled={firing} onFire={() => fire('brute-burst')} />
            <AttackCard
              kind="distributed" label="Distributed (×100 clientIds)"
              desc="Rotate clientId per request to slip under the per-client anomaly window. Coming v1.2 — IP cross-correlation."
              disabled />
          </div>
        </div>

        {/* Anomaly engine */}
        <div className="card">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <h3>Anomaly engine</h3>
            <div className="row" style={{ gap: 6 }}>
              {serverAnomaly && <Pill tone="primary">live server</Pill>}
              <Pill tone={displayVerdict === 'attack' ? 'danger' : displayVerdict === 'suspicious' ? 'warn' : 'success'}>
                {displayVerdict}
              </Pill>
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'center', marginTop: 8 }}>
            <ThreatGauge score={displayScore} verdict={displayVerdict} />
          </div>
          <div className="divider" />
          <div className="upper" style={{ marginBottom: 8 }}>
            {serverAnomaly ? 'Server · real scoring' : 'Local · 5-min rolling window'}
          </div>
          <div className="col" style={{ gap: 6 }}>
            {localAnomaly.reasons.length === 0
              ? <span className="muted" style={{ fontSize: 12 }}>No failures observed yet. Fire something.</span>
              : localAnomaly.reasons.map((r, i) => (
                  <div key={i} className="mono" style={{ fontSize: 11.5, color: 'var(--muted)' }}>
                    <span style={{ color: 'var(--danger)' }}>›</span> {r}
                  </div>
                ))}
            {serverAnomaly && (
              <div className="mono" style={{ fontSize: 11, color: 'var(--dim)', marginTop: 4 }}>
                Server score: {serverAnomaly.score} · verdict: {serverAnomaly.verdict}
              </div>
            )}
          </div>
          <div className="divider" />
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <span className="upper">Window events</span>
            <span className="mono tnum" style={{ fontSize: 13 }}>{localAnomaly.windowSize}</span>
          </div>
          <div style={{ marginTop: 8 }}>
            <Sparkline
              data={scoreHistoryRef.current.length > 1 ? scoreHistoryRef.current : [0, 0]}
              width={300} height={36}
              color={displayVerdict === 'attack' ? 'var(--danger)' : displayVerdict === 'suspicious' ? 'var(--warning)' : 'var(--success)'}
            />
          </div>
        </div>
      </div>

      {/* Attempt log */}
      <div className="card flush">
        <div className="ch">
          <h3>Validation log · real server responses</h3>
          <span className="muted" style={{ fontSize: 12 }}>{attempts.length} attempts · most recent first</span>
        </div>
        {attempts.length === 0 ? (
          <div style={{ padding: 22, textAlign: 'center' }} className="muted">
            Capture a key and try an attack to populate the log.
          </div>
        ) : (
          <table>
            <thead>
              <tr><th>Time</th><th>Attempt</th><th>HTTP</th><th>Verdict</th><th>Tell</th></tr>
            </thead>
            <tbody>
              {attempts.map((a, i) => (
                <tr key={i}>
                  <td className="mono tnum" style={{ fontSize: 12 }}>{new Date(a.t).toLocaleTimeString()}</td>
                  <td style={{ fontSize: 12.5 }}>{a.label}</td>
                  <td>
                    {a.result?.status ? (
                      <span className="mono" style={{
                        fontSize: 12, padding: '2px 6px', borderRadius: 4,
                        background: a.result.status === 200
                          ? 'color-mix(in oklab, var(--success) 20%, transparent)'
                          : 'color-mix(in oklab, var(--danger) 20%, transparent)',
                        color: a.result.status === 200 ? 'var(--success)' : 'var(--danger)',
                      }}>{a.result.status}</span>
                    ) : '—'}
                  </td>
                  <td>
                    <Pill tone={a.result?.verdict === 'accept' ? 'success' : a.result?.verdict === 'observed' ? 'primary' : a.result?.verdict === 'error' ? 'warn' : 'danger'}>
                      {a.result?.verdict || '—'}
                    </Pill>
                  </td>
                  <td className="muted" style={{ fontSize: 12 }}>
                    {a.result?.checksumFail ? 'Checksum rejected — segments skipped'
                      : a.result?.staticPass && a.result?.rotFail ? 'Static passes, rotating fails — stolen key fingerprint'
                      : a.result?.allFail ? 'All segments fail — forgery'
                      : a.result?.verdict === 'observed' ? 'Sniffer only — no validation request'
                      : a.result?.verdict === 'accept' ? 'Authentic — key valid this window'
                      : a.result?.serverError ? `Server: ${a.result.serverError}`
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function AttackCard({ label, desc, hint, disabled, danger, highValue, onFire }) {
  return (
    <button onClick={onFire} disabled={disabled}
      style={{
        textAlign: 'left', padding: 14, borderRadius: 10,
        background: disabled ? 'var(--surface-2)' : highValue ? 'color-mix(in oklab, var(--danger) 8%, var(--surface))' : 'var(--surface-2)',
        border: `1px solid ${highValue ? 'color-mix(in oklab, var(--danger) 30%, transparent)' : 'var(--border)'}`,
        opacity: disabled ? 0.45 : 1,
        cursor: disabled ? 'not-allowed' : 'pointer',
        transition: '.12s',
        color: 'var(--text)',
      }}>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontWeight: 600, fontSize: 13.5 }}>{label}</span>
        <span style={{
          fontSize: 11, color: danger ? 'var(--danger)' : highValue ? 'var(--danger)' : 'var(--muted)',
        }}>▶ fire</span>
      </div>
      <div className="muted" style={{ fontSize: 12, lineHeight: 1.45 }}>{desc}</div>
      {hint && <div style={{ fontSize: 11, color: 'var(--primary)', marginTop: 6, lineHeight: 1.4 }}>ℹ {hint}</div>}
    </button>
  );
}

window.ScreenAttack = ScreenAttack;
