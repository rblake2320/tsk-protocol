// screen-stack.jsx — composed BPC + TSK verification visualizer

const STACK_LAYERS = [
  { n: 1, group: 'bpc', title: 'Authorized ECDSA P-256 pair key', prop: 'Pair-key possession; hardware attestation is not implied',
    detail: 'The request must carry a signature made by the registered pair key. Non-exportable WebCrypto configuration is not hardware attestation.' },
  { n: 2, group: 'bpc', title: 'Explicit pair registry',        prop: 'Closed whitelist of allowed device↔service pairs',
    detail: 'Requests are bound to a registered pair tuple. Unknown pairs are rejected before any cryptographic work runs.' },
  { n: 3, group: 'bpc', title: 'User-secret HMAC binding',      prop: 'User-chosen secret HMAC\'d into every signature',
    detail: 'Deployment-provisioned secret material is HMAC-bound to the signed request. Secret custody remains a deployment responsibility.' },
  { n: 4, group: 'bpc', title: 'Per-request nonce + timestamp', prop: '256-bit nonce · ±60s server clock window',
    detail: 'Anti-replay at the request level. A captured BPC signature is rejected after 60 seconds — independent of TSK rotation.' },
  { n: 5, group: 'bpc', title: 'Behavioral anomaly engine',     prop: 'Per-pair threat scoring · IP cross-correlation',
    detail: 'Failure patterns can be scored per pair and source context. Scores are telemetry and require deployment policy.' },
  { n: 6, group: 'tsk', title: 'Derived segment credential', prop: 'Static, time-window, and counter schedules',
    detail: 'The provisioned client and server derive values from the same shared secret. Layout boundaries are visible to the client.' },
  { n: 7, group: 'tsk', title: 'Atomic state transition', prop: 'All counters and lifecycle usage commit together',
    detail: 'Replay-sensitive state and the hard request cap are checked and committed in one store transaction.' },
];

function ScreenStack() {
  const [open, setOpen] = useState(7);

  return (
    <div className="col" style={{ gap: 24 }}>
      <SectionHead
        eyebrow="Full Stack · port 3100"
        title="Two verifiers. One mandatory identity binding."
        sub="BPC pair-key verification and TSK shared-secret validation must both succeed and resolve to the same principal. Application authorization follows."
        right={
          <div className="row" style={{ gap: 8 }}>
            <Pill>BPC · 5 layers</Pill>
            <Pill tone="primary">TSK · 2 layers</Pill>
          </div>
        }
      />

      {/* Stack visual */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 16, alignItems: 'flex-start' }}>
        <div className="col" style={{ gap: 8 }}>
          {STACK_LAYERS.slice().reverse().map((layer) => (
            <button key={layer.n}
              className={`layer ${layer.group}`}
              onClick={() => setOpen(open === layer.n ? null : layer.n)}
              style={{
                width: '100%', textAlign: 'left',
                cursor: 'pointer', position: 'relative',
                outline: open === layer.n ? '1px solid var(--primary)' : 'none',
                boxShadow: open === layer.n ? '0 0 0 3px var(--primary-soft)' : 'none',
              }}>
              <div className="num">{String(layer.n).padStart(2, '0')}</div>
              <div>
                <div className="lt">
                  {layer.title}
                </div>
                <div className="ld">{layer.prop}</div>
              </div>
              <div className="row" style={{ gap: 8 }}>
                <Pill tone={layer.group === 'bpc' ? 'default' : layer.group === 'tsk' ? 'primary' : 'warn'}>
                  {layer.group.toUpperCase()}
                </Pill>
                <span className="dim" style={{ fontSize: 14 }}>{open === layer.n ? '−' : '+'}</span>
              </div>
              {open === layer.n && (
                <div style={{ gridColumn: '1 / -1', paddingTop: 12, borderTop: '1px solid var(--border)',
                  marginTop: 4, fontSize: 13, color: 'var(--muted)', lineHeight: 1.6 }}>
                  {layer.detail}
                </div>
              )}
            </button>
          ))}
        </div>

        {/* Visual rail */}
        <div className="col" style={{ gap: 16 }}>
          <div className="card">
            <h3 style={{ marginBottom: 12 }}>Verification flow</h3>
            <div className="col" style={{ gap: 10 }}>
              <FlowStep n={1} title="Request arrives"
                detail="X-BPC-Signature · X-BPC-Nonce · X-BPC-Timestamp · X-TSK-Client-ID · X-TSK-Key" />
              <FlowArrow />
              <FlowStep n={2} title="BPC: pair + signature + freshness"
                detail="Verify the registered pair, request binding, signature, and freshness; record the nonce only after cryptographic checks pass." accent="static" />
              <FlowArrow />
              <FlowStep n={3} title="TSK: integrity tag first"
                detail="The truncated HMAC tag is compared before individual segment validation." accent="checksum" />
              <FlowArrow />
              <FlowStep n={4} title="TSK: per-segment validation"
                detail="Equal-length candidates use timingSafeEqual. Each pass/fail feeds the anomaly engine." accent="totp" />
              <FlowArrow />
              <FlowStep n={5} title="Atomic state commit"
                detail="All matched counters and lifecycle usage commit together; replay or cap conflicts deny." accent="hotp" />
              <FlowArrow />
              <FlowStep n={6} title="Identity match and application policy"
                detail="The bridge denies mismatched principals. The application then enforces the verified BPC scope." />
            </div>
          </div>

          <div className="card">
            <Pill tone="warn">DEPLOYMENT BOUNDARY</Pill>
            <h3 style={{ marginTop: 10, fontSize: 17 }}>Authentication is not authorization.</h3>
            <p style={{ marginTop: 8, fontSize: 13 }}>
              TLS, operator identity, resource policy, secret custody, durable distributed state,
              audit evidence, monitoring, and recovery must be supplied and assessed by the deployment.
            </p>
          </div>
        </div>
      </div>

      {/* Cross-installations */}
      <div className="card">
        <SectionHead
          title="Three deployments, two ports, one protocol."
          sub="The TSK-only demo runs on port 3200. The composed BPC + TSK verifier runs on port 3100."
        />
        <div className="g3" style={{ marginTop: 16 }}>
          <DeploymentCard
            badge="port 3200" badgeTone="primary"
            title="TSK Standalone"
            stat="2 layers · 6 + 7"
            desc="The protocol on its own. Drop into any HMAC-friendly stack. No hardware dependencies." />
          <DeploymentCard
            badge="port 3100" badgeTone="warn"
            title="Composed verifier"
            stat="BPC + TSK"
            desc="Both protocol checks plus mandatory principal identity binding. Deployment authorization remains separate." />
          <DeploymentCard
            badge="standalone" badgeTone="default"
            title="BPC Standalone"
            stat="5 layers · 1 through 5"
            desc="Authorized pair-key request verification plus behavioral telemetry." />
        </div>
      </div>
    </div>
  );
}

function FlowStep({ n, title, detail, accent }) {
  return (
    <div className="row" style={{ alignItems: 'flex-start', gap: 12, padding: '10px 12px',
      borderRadius: 8, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
      <span style={{
        width: 22, height: 22, borderRadius: 99, fontSize: 11, fontWeight: 700,
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        background: accent ? `color-mix(in oklab, var(--${accent}) 24%, transparent)` : 'var(--surface-2)',
        color: accent ? `var(--${accent})` : 'var(--muted)',
        flexShrink: 0,
      }}>{n}</span>
      <div>
        <div style={{ fontSize: 13, fontWeight: 600 }}>{title}</div>
        <div className="muted mono" style={{ fontSize: 11, marginTop: 3 }}>{detail}</div>
      </div>
    </div>
  );
}
function FlowArrow() {
  return <div className="dim" style={{ textAlign: 'center', fontSize: 12, lineHeight: 0.4 }}>↓</div>;
}

function DeploymentCard({ badge, badgeTone, title, stat, desc }) {
  return (
    <div className="card" style={{ padding: 18 }}>
      <Pill tone={badgeTone}>{badge}</Pill>
      <h3 style={{ marginTop: 10, fontSize: 16 }}>{title}</h3>
      <div className="mono tnum" style={{ fontSize: 13, color: 'var(--primary)', marginTop: 4, fontWeight: 500 }}>
        {stat}
      </div>
      <p style={{ marginTop: 8, fontSize: 12.5 }}>{desc}</p>
    </div>
  );
}

window.ScreenStack = ScreenStack;
