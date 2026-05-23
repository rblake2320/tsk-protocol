// app.jsx — App shell: sidebar nav, topbar, screen router, tweaks panel.
// Modified from design: waits for DEMO_MAP to be provisioned from server before rendering screens.

const TWEAK_DEFAULTS = {
  "accent": "blue",
  "density": "regular",
  "contrast": "normal",
  "showPositions": true
};

const SCREENS = [
  { id: 'overview',  label: 'Overview',      group: 'Main',        comp: 'ScreenOverview',  hint: 'Landing · pitch' },
  { id: 'vault',     label: 'Live Vault',    group: 'Protocol',    comp: 'ScreenVault',     hint: 'Tumbling key' },
  { id: 'attack',    label: 'Attack Lab',    group: 'Protocol',    comp: 'ScreenAttack',    hint: 'Replay · forge · anomaly' },
  { id: 'provision', label: 'Provisioning',  group: 'Protocol',    comp: 'ScreenProvision', hint: 'Mint clients' },
  { id: 'stack',     label: '8-Layer Stack', group: 'Architecture',comp: 'ScreenStack',     hint: 'BPC + TSK + Active Defense' },
  { id: 'about',     label: 'About',         group: 'Info',        comp: 'ScreenAbout',     hint: 'Protocol · inventor · access' },
];

function App() {
  const [route, setRoute] = useState(() => {
    const h = location.hash.replace('#', '');
    return SCREENS.find(s => s.id === h) ? h : 'overview';
  });
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [mapReady, setMapReady] = useState(!!window.DEMO_MAP);
  const [serverStatus, setServerStatus] = useState('checking'); // checking | ok | error
  const [bpcStatus, setBpcStatus] = useState('checking'); // checking | ok | offline

  // Wait for DEMO_MAP to be provisioned
  useEffect(() => {
    if (window.DEMO_MAP) { setMapReady(true); setServerStatus('ok'); return; }
    window.DEMO_MAP_READY.then(map => {
      if (map) { setMapReady(true); setServerStatus('ok'); }
      else setServerStatus('error');
    });
  }, []);

  // Probe BPC server at :3101 (BPC-only demo) for real status
  useEffect(() => {
    const ctrl = new AbortController();
    fetch('http://localhost:3101/', { signal: ctrl.signal, cache: 'no-store' })
      .then(r => setBpcStatus(r.ok || r.status < 500 ? 'ok' : 'offline'))
      .catch(() => setBpcStatus('offline'))
      .finally(() => {});
    return () => ctrl.abort();
  }, []);

  // Sync body attrs for tweak themes
  useEffect(() => {
    document.body.dataset.accent = t.accent;
    document.body.dataset.density = t.density;
    document.body.dataset.contrast = t.contrast;
  }, [t.accent, t.density, t.contrast]);

  // Hash routing
  useEffect(() => {
    const onHash = () => {
      const h = location.hash.replace('#', '');
      if (SCREENS.find(s => s.id === h)) setRoute(h);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  // Track screen views
  useEffect(() => {
    if (typeof trackEvent === 'function') trackEvent('screen_view', { screen: route });
  }, [route]);

  // Keyboard nav: g + v/a/p/s/o/b
  useEffect(() => {
    let waiting = false;
    const onKey = e => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      if (e.key === 'g' || e.key === 'G') { waiting = true; setTimeout(() => (waiting = false), 1000); return; }
      if (!waiting) return;
      const m = { o: 'overview', v: 'vault', a: 'attack', p: 'provision', s: 'stack', b: 'about' };
      if (m[e.key]) { goto(m[e.key]); waiting = false; }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const goto = id => {
    location.hash = id;
    setRoute(id);
    window.scrollTo({ top: 0, behavior: 'instant' });
  };

  const currentScreen = SCREENS.find(s => s.id === route);
  const ScreenComp = window[currentScreen.comp];
  const grouped = SCREENS.reduce((acc, s) => ((acc[s.group] = acc[s.group] || []).push(s), acc), {});

  return (
    <div className="app" data-screen-label={currentScreen.label}>
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="row" style={{ gap: 10, padding: '4px 8px 16px' }}>
          <Logo size={26} />
          <div>
            <div style={{ fontWeight: 700, letterSpacing: '-0.01em', fontSize: 14 }}>TSK</div>
            <div className="mono" style={{ fontSize: 10.5, color: 'var(--dim)' }}>tumbler protocol</div>
          </div>
        </div>

        {Object.entries(grouped).map(([group, items]) => (
          <div key={group}>
            <div className="nav-section">{group}</div>
            {items.map(s => (
              <a key={s.id} href={`#${s.id}`}
                className={`nav-item ${route === s.id ? 'active' : ''}`}
                onClick={e => { e.preventDefault(); goto(s.id); }}>
                <span className="dot" style={{
                  background: route === s.id ? 'var(--primary)' : 'currentColor',
                  boxShadow: route === s.id ? '0 0 8px var(--primary)' : 'none',
                }} />
                <span style={{ flex: 1 }}>{s.label}</span>
                <span className="dim mono" style={{ fontSize: 10 }}>g{s.id[0]}</span>
              </a>
            ))}
          </div>
        ))}

        <div style={{ marginTop: 'auto', padding: '14px 8px 0', borderTop: '1px solid var(--border)' }}>
          <div className="upper" style={{ marginBottom: 8 }}>Status</div>
          <div className="row" style={{ gap: 8, marginBottom: 6 }}>
            <span className="live-dot" style={{
              background: serverStatus === 'ok' ? 'var(--success)' : serverStatus === 'error' ? 'var(--danger)' : 'var(--warning)',
              boxShadow: `0 0 10px ${serverStatus === 'ok' ? 'var(--success)' : serverStatus === 'error' ? 'var(--danger)' : 'var(--warning)'}`,
            }} />
            <span className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>
              tsk-server :3200 {serverStatus === 'ok' ? '✓' : serverStatus === 'error' ? '✗' : '…'}
            </span>
          </div>
          <div className="row" style={{ gap: 8, marginBottom: 6 }}>
            <span className="live-dot" />
            <span className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>full-stack :3100</span>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <span className="live-dot" style={{
              background: bpcStatus === 'ok' ? 'var(--success)' : bpcStatus === 'offline' ? 'var(--border-2)' : 'var(--warning)',
              boxShadow: bpcStatus === 'ok' ? '0 0 10px var(--success)' : 'none',
            }} />
            <span className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>
              bpc-bridge :3101 {bpcStatus === 'ok' ? '✓' : bpcStatus === 'offline' ? 'offline' : '…'}
            </span>
          </div>
          {mapReady && window.DEMO_MAP && (
            <div style={{ marginTop: 10 }}>
              <div className="upper" style={{ marginBottom: 4 }}>Client</div>
              <div className="mono" style={{ fontSize: 10, color: 'var(--dim)', wordBreak: 'break-all' }}>
                {window.DEMO_MAP.clientId}
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* Topbar */}
      <header className="topbar">
        <div className="row" style={{ gap: 14 }}>
          <Crumbs route={route} />
        </div>
        <div className="row" style={{ gap: 14 }}>
          <Pill tone={serverStatus === 'ok' ? 'success' : serverStatus === 'error' ? 'danger' : 'warn'}>
            <span className="live-dot" style={{
              background: serverStatus === 'ok' ? 'var(--success)' : serverStatus === 'error' ? 'var(--danger)' : 'var(--warning)',
            }} />
            {serverStatus === 'ok' ? 'all systems nominal' : serverStatus === 'error' ? 'server unreachable' : 'connecting…'}
          </Pill>
          <span className="muted" style={{ fontSize: 12 }}>
            <span className="kbd">G</span> then <span className="kbd">V/A/P/S/O</span> to jump
          </span>
          <div className="row" style={{ gap: 4 }}>
            <button className="btn sm ghost"
              onClick={() => window.open('http://localhost:3100', '_blank')}>Full stack ↗</button>
            <button className="btn sm ghost">Spec v1.1</button>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="main" key={route}>
        {!mapReady
          ? <LoadingScreen status={serverStatus} />
          : <ScreenComp goto={goto} />
        }
      </main>

      {/* Tweaks panel */}
      <TweaksPanel>
        <TweakSection label="Theme · accent" />
        <TweakRadio label="Accent" value={t.accent}
          options={['blue', 'cyan', 'violet']}
          onChange={v => setTweak('accent', v)} />
        <TweakSection label="Layout · density" />
        <TweakRadio label="Density" value={t.density}
          options={['compact', 'regular', 'spacious']}
          onChange={v => setTweak('density', v)} />
        <TweakSection label="Contrast" />
        <TweakRadio label="Mode" value={t.contrast}
          options={['normal', 'high']}
          onChange={v => setTweak('contrast', v)} />
        <TweakSection label="Reveal" />
        <TweakToggle label="Show positions in tables" value={t.showPositions}
          onChange={v => setTweak('showPositions', v)} />
      </TweaksPanel>
    </div>
  );
}

function LoadingScreen({ status }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
      height: '60vh', flexDirection: 'column', gap: 20 }}>
      <Logo size={40} />
      {status === 'error' ? (
        <>
          <h3 style={{ color: 'var(--danger)' }}>Cannot reach TSK server</h3>
          <p className="muted" style={{ fontSize: 13, textAlign: 'center', maxWidth: 400 }}>
            Start the server first: <code className="mono" style={{ color: 'var(--text)' }}>cd demo && npx tsx server.ts</code>
          </p>
        </>
      ) : (
        <>
          <h3 style={{ color: 'var(--muted)' }}>Provisioning demo client…</h3>
          <p className="muted" style={{ fontSize: 13 }}>
            Connecting to <span className="mono">localhost:3200</span>
          </p>
        </>
      )}
    </div>
  );
}

function Crumbs({ route }) {
  const s = SCREENS.find(x => x.id === route);
  return (
    <div className="row" style={{ gap: 8 }}>
      <span className="muted" style={{ fontSize: 13 }}>TSK Protocol</span>
      <span className="dim">/</span>
      <span className="muted" style={{ fontSize: 13 }}>{s.group}</span>
      <span className="dim">/</span>
      <span style={{ fontSize: 13, fontWeight: 500 }}>{s.label}</span>
      <span className="dim mono" style={{ fontSize: 11, marginLeft: 6 }}>{s.hint}</span>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
