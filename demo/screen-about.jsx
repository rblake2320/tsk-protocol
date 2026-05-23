// screen-about.jsx — About TSK Protocol: who, what, why, access, links

function ScreenAbout({ goto }) {
  useEffect(() => {
    trackEvent('screen_view', { screen: 'about' });
  }, []);

  const handleRequestAccess = () => {
    trackEvent('cta_click', { cta: 'request_access', screen: 'about' });
  };

  return (
    <div className="col" style={{ gap: 36, maxWidth: 900 }}>
      <SectionHead
        eyebrow="About"
        title="TSK Protocol"
        sub="Tumbler-Style Rotating Segment Keys — a novel API authentication protocol where the key's internal structure is itself a secret."
      />

      {/* Protocol identity */}
      <div className="g2" style={{ gap: 20 }}>
        <div className="card" style={{ padding: 28 }}>
          <div className="upper" style={{ color: 'var(--primary)', marginBottom: 12 }}>What it is</div>
          <h3 style={{ fontSize: 20, marginBottom: 12, letterSpacing: '-0.02em' }}>
            An API key that is structurally secret.
          </h3>
          <p style={{ fontSize: 14, lineHeight: 1.65 }}>
            TSK is an authentication protocol where an API key is composed of independently-rotating
            segments whose <strong style={{ color: 'var(--text)' }}>positional map is a per-client
            server secret</strong>. The client generates segments. The server holds their positions.
            Neither party can reconstruct what the other knows.
          </p>
          <div className="divider" />
          <p style={{ fontSize: 13, lineHeight: 1.6 }}>
            A captured TSK key cannot be replayed after its shortest segment window. A forged key
            cannot pass without knowing the exact positional map. An attacker who exfiltrates the
            client SDK learns <em>which</em> segments exist — not <em>where</em> they live.
          </p>
        </div>

        <div className="col" style={{ gap: 16 }}>
          <div className="card" style={{ padding: 20 }}>
            <div className="upper" style={{ color: 'var(--primary)', marginBottom: 10 }}>Status</div>
            <div className="row" style={{ gap: 10, marginBottom: 8 }}>
              <Pill tone="primary">
                <span className="live-dot" style={{ background: 'var(--primary)', boxShadow: '0 0 10px var(--primary)' }} />
                Patent-pending · v1.1
              </Pill>
            </div>
            <p style={{ fontSize: 13, lineHeight: 1.55 }}>
              Provisional patent filed. The core novelty — structural secrecy, per-client
              randomized positional maps, and independent segment rotation — has no equivalent
              in existing standards or prior art.
            </p>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div className="upper" style={{ marginBottom: 10 }}>Inventor</div>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>R. Blake</div>
            <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>
              All rights reserved. Confidential pre-patent-filing intellectual property.
              Do not distribute without authorization.
            </p>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div className="upper" style={{ marginBottom: 10 }}>Version history</div>
            <div className="col" style={{ gap: 8 }}>
              {[
                { v: 'v1.1', date: '2026-05-18', note: 'IL4/5/6/7 hardening — 72-bit checksum, atomic HOTP CAS, structural secrecy fixes' },
                { v: 'v1.0', date: '2026-04-09', note: 'Initial specification — tumbler map, TOTP/HOTP segments, anomaly engine' },
              ].map(r => (
                <div key={r.v} className="row" style={{ gap: 12, alignItems: 'flex-start' }}>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--primary)', minWidth: 32 }}>{r.v}</span>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--dim)', minWidth: 80 }}>{r.date}</span>
                  <span style={{ fontSize: 12, color: 'var(--muted)' }}>{r.note}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Security properties summary */}
      <div className="card">
        <h3 style={{ marginBottom: 16 }}>Core security properties</h3>
        <div className="g3" style={{ gap: 14 }}>
          {[
            { label: 'Structural secrecy', desc: 'The positional map — which characters rotate, at what rate, and where they live — is a server-side secret never transmitted after provisioning.' },
            { label: 'Independent rotation', desc: 'TOTP segments expire independently on 30–300s windows. HOTP segments are one-shot. Static segment anchors client identity.' },
            { label: 'Checksum-first reject', desc: '72-bit HMAC checksum validates before any segment is touched. Rejects 1 − 2⁻⁷² of forgeries in O(1) — DoS-resistant by design.' },
            { label: 'Atomic HOTP CAS', desc: 'HOTP counter advances via compare-and-swap. Concurrent replay of the same key across threads is blocked at the store layer.' },
            { label: 'Anomaly fingerprinting', desc: 'Per-segment pass/fail results feed the anomaly engine. Static-passes-rotating-fails is a unique stolen-key fingerprint.' },
            { label: 'BPC composability', desc: 'Stack TSK behind device-bound ECDSA (BPC) for a 7-layer orthogonal factor stack. Two independent attack surfaces, one bridge.' },
          ].map(p => (
            <div key={p.label} style={{ padding: '14px 16px', borderRadius: 10,
              background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>{p.label}</div>
              <p style={{ fontSize: 12, lineHeight: 1.5 }}>{p.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Three-site architecture */}
      <div className="card">
        <h3 style={{ marginBottom: 4 }}>Three demo deployments</h3>
        <p className="muted" style={{ fontSize: 13, marginBottom: 16 }}>
          Each site runs a real backend with no mocks. All demos share the same protocol implementation.
        </p>
        <div className="g3">
          {[
            {
              port: ':3200', label: 'TSK Standalone', current: true,
              desc: 'Layers 6 + 7. Tumbler key + structural secrecy. This site.',
              tone: 'primary',
            },
            {
              port: ':3100', label: 'Full 8-Layer Stack',
              desc: 'BPC (1–5) + TSK (6–7) + Active Defense (8). The flagship.',
              tone: 'warn', href: 'http://localhost:3100',
            },
            {
              port: ':3101', label: 'BPC Standalone',
              desc: 'Layers 1–5. Device-bound ECDSA + behavioral anomaly engine.',
              tone: 'default', href: 'http://localhost:3101',
            },
          ].map(s => (
            <div key={s.port} className="card" style={{
              padding: 18,
              outline: s.current ? '1px solid var(--primary)' : 'none',
              boxShadow: s.current ? '0 0 0 3px var(--primary-soft)' : 'none',
            }}>
              <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
                <Pill tone={s.tone}>{s.port}</Pill>
                {s.current && <span className="mono" style={{ fontSize: 10, color: 'var(--primary)' }}>YOU ARE HERE</span>}
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6 }}>{s.label}</div>
              <p style={{ fontSize: 12.5, marginBottom: s.href ? 12 : 0 }}>{s.desc}</p>
              {s.href && (
                <a href={s.href} target="_blank"
                  onClick={() => trackEvent('cta_click', { cta: 'site_link', target: s.port })}
                  style={{ fontSize: 12, color: 'var(--primary)' }}>
                  Open ↗
                </a>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Request access CTA */}
      <div className="card" style={{
        background: 'linear-gradient(135deg, var(--primary-soft), transparent 60%), var(--surface)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        gap: 24, flexWrap: 'wrap', padding: 28,
      }}>
        <div>
          <h2 style={{ fontSize: 22, marginBottom: 8 }}>Interested in TSK?</h2>
          <p style={{ fontSize: 14, maxWidth: 520 }}>
            TSK is pre-release and patent-pending. For licensing inquiries, integration
            partnerships, or early access, reach out directly.
          </p>
        </div>
        <div className="col" style={{ gap: 10, alignItems: 'flex-start' }}>
          <button className="btn primary" onClick={handleRequestAccess}
            style={{ fontSize: 14 }}>
            Request access
          </button>
          <button className="btn sm ghost" onClick={() => goto('stack')}>
            View the 8-layer stack →
          </button>
        </div>
      </div>

      {/* Legal footer */}
      <div style={{ padding: '16px 0', borderTop: '1px solid var(--border)' }}>
        <p className="mono" style={{ fontSize: 11, color: 'var(--dim)', lineHeight: 1.7 }}>
          CONFIDENTIAL — Pre-patent-filing intellectual property of R. Blake. All rights reserved.
          This document and its contents may not be reproduced or distributed without written authorization.
          TSK Protocol v1.1 · Provisional patent pending · © 2026 R. Blake
        </p>
      </div>
    </div>
  );
}

window.ScreenAbout = ScreenAbout;
