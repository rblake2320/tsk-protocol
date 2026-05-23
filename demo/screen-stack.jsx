// screen-stack.jsx — 8-layer stack visualizer (BPC + TSK + Active Defense)

const STACK_LAYERS = [
  { n: 1, group: 'bpc', title: 'Device-bound ECDSA P-256',     prop: 'TPM / Secure Enclave key · extractable: false',
    detail: 'Hardware-backed signing key generated at first launch. Private material never leaves the device, never appears in JS heap.' },
  { n: 2, group: 'bpc', title: 'Explicit pair registry',        prop: 'Closed whitelist of allowed device↔service pairs',
    detail: 'Requests are bound to a registered pair tuple. Unknown pairs are rejected before any cryptographic work runs.' },
  { n: 3, group: 'bpc', title: 'User-secret HMAC binding',      prop: 'User-chosen secret HMAC\'d into every signature',
    detail: 'A short user secret (passphrase / PIN) is mixed into the signature digest. Knowledge factor; survives device theft.' },
  { n: 4, group: 'bpc', title: 'Per-request nonce + timestamp', prop: '256-bit nonce · ±60s server clock window',
    detail: 'Anti-replay at the request level. A captured BPC signature is rejected after 60 seconds — independent of TSK rotation.' },
  { n: 5, group: 'bpc', title: 'Behavioral anomaly engine',     prop: 'Per-pair threat scoring · IP cross-correlation',
    detail: 'Failure patterns are scored per device-service pair. Slow-drip evasion countered by IP rate-binding (v1.1 hardening).' },
  { n: 6, group: 'tsk', title: 'Tumbler key · positional secret',prop: 'Per-client randomized segment positions, server-only',
    detail: 'Each client gets its own positional map. Length, ordering, and segment count are server secrets — never shipped.' },
  { n: 7, group: 'tsk', title: 'Structural secrecy',            prop: 'Provision payload omits positions, lengths, ordering',
    detail: 'A captured client SDK reveals which segments exist by ID — not where in the string they live. No structural inference.' },
  { n: 8, group: 'l8',  title: 'Active Defense',                prop: 'Honeypot segments · auto-rotate on anomaly burst',
    detail: 'NEW IN v1.2. Decoy segments seed the key with known-bad positions; touching them triggers immediate full rotation and tenant alert.' },
];

function ScreenStack() {
  const [open, setOpen] = useState(8);

  return (
    <div className="col" style={{ gap: 24 }}>
      <SectionHead
        eyebrow="Full Stack · port 3100"
        title="Eight independent layers. One bridge."
        sub="BPC supplies hardware identity. TSK supplies key secrecy. Active Defense supplies counter-intelligence. An attacker must defeat every layer simultaneously."
        right={
          <div className="row" style={{ gap: 8 }}>
            <Pill>BPC · 5 layers</Pill>
            <Pill tone="primary">TSK · 2 layers</Pill>
            <Pill tone="warn">Active Defense · 1 layer</Pill>
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
                  {layer.group === 'l8' && (
                    <Pill tone="warn" style={{ marginLeft: 10 }}>NEW · v1.2</Pill>
                  )}
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
                detail="verifyBPCRequest() — pure function, no side effects. Reject before TSK touches CPU." accent="static" />
              <FlowArrow />
              <FlowStep n={3} title="TSK: checksum first"
                detail="HMAC tail compared. Rejects 1 − 2⁻⁷² of forgeries before any segment lookup." accent="checksum" />
              <FlowArrow />
              <FlowStep n={4} title="TSK: per-segment validation"
                detail="Constant-time compare per segment. Each pass/fail feeds the anomaly engine." accent="totp" />
              <FlowArrow />
              <FlowStep n={5} title="Active Defense: tripwire check"
                detail="If a request touches a honeypot segment, full rotation + tenant alert." accent="hotp" />
              <FlowArrow />
              <FlowStep n={6} title="Accept · or anomaly-scored reject"
                detail="200 OK, or 401 + threat-score header. Anomaly engine updates in O(1)." />
            </div>
          </div>

          <div className="card" style={{
            background: 'linear-gradient(135deg, color-mix(in oklab, var(--hotp) 12%, var(--surface)), var(--surface))',
          }}>
            <Pill tone="warn">v1.2 · ACTIVE DEFENSE</Pill>
            <h3 style={{ marginTop: 10, fontSize: 17 }}>Layer 8 turns defense into intelligence.</h3>
            <p style={{ marginTop: 8, fontSize: 13 }}>
              Honeypot segments are statistically indistinguishable from real ones on the wire. An attacker who reverses
              SDK state and submits a forged key has a non-zero probability of touching one. The instant they do — the
              full tumbler map is rotated, the tenant is paged, and the originating fingerprint is broadcast across all
              federated TSK installations.
            </p>
            <div className="divider" />
            <div className="g3">
              <Stat label="Honeypot hit rate" value="3.1%" sub="random forgeries" accent="var(--hotp)" />
              <Stat label="Time to rotate" value="< 80ms" sub="map regenerated" accent="var(--hotp)" />
              <Stat label="False positives" value="0" sub="legit clients never touch them" accent="var(--success)" />
            </div>
          </div>
        </div>
      </div>

      {/* Cross-installations */}
      <div className="card">
        <SectionHead
          title="Three deployments, two ports, one protocol."
          sub="The TSK-only demo runs on port 3200. The full 8-layer flagship — BPC + TSK + Active Defense — runs on port 3100. Both are wire-compatible with the same client SDK."
        />
        <div className="g3" style={{ marginTop: 16 }}>
          <DeploymentCard
            badge="port 3200" badgeTone="primary"
            title="TSK Standalone"
            stat="2 layers · 6 + 7"
            desc="The protocol on its own. Drop into any HMAC-friendly stack. No hardware dependencies." />
          <DeploymentCard
            badge="port 3100" badgeTone="warn"
            title="Full 8-layer flagship"
            stat="8 layers · 1 through 8"
            desc="BPC + TSK + Active Defense. The full stack for high-value APIs — finance, defense, infra control planes." />
          <DeploymentCard
            badge="standalone" badgeTone="default"
            title="BPC Standalone"
            stat="5 layers · 1 through 5"
            desc="Device-bound ECDSA + behavioral engine. For APIs without rotating-key requirements." />
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
