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
        sub="Tumbler-Style Rotating Segment Keys — a beta shared-secret protocol with independently derived segment schedules."
      />

      {/* Protocol identity */}
      <div className="g2" style={{ gap: 20 }}>
        <div className="card" style={{ padding: 28 }}>
          <div className="upper" style={{ color: 'var(--primary)', marginBottom: 12 }}>What it is</div>
          <h3 style={{ fontSize: 20, marginBottom: 12, letterSpacing: '-0.02em' }}>
            A credential with rotating server-held state.
          </h3>
          <p style={{ fontSize: 14, lineHeight: 1.65 }}>
            TSK composes static, time-window, and counter-based HMAC-SHA-256 values.
            The server retains authoritative counters and lifecycle state. Ordered segment
            lengths reveal the layout, so security does not depend on hiding it.
          </p>
          <div className="divider" />
          <p style={{ fontSize: 13, lineHeight: 1.6 }}>
            Generated credentials include a counter-based segment, and the bundled stores consume
            counter and usage state atomically. Shared-secret compromise remains a credential
            compromise and requires revocation or authorized replacement.
          </p>
        </div>

        <div className="col" style={{ gap: 16 }}>
          <div className="card" style={{ padding: 20 }}>
            <div className="upper" style={{ color: 'var(--primary)', marginBottom: 10 }}>Status</div>
            <div className="row" style={{ gap: 10, marginBottom: 8 }}>
              <Pill tone="primary">
                <span className="live-dot" style={{ background: 'var(--primary)', boxShadow: '0 0 10px var(--primary)' }} />
                Beta reference · wire v1
              </Pill>
            </div>
            <p style={{ fontSize: 13, lineHeight: 1.55 }}>
              Patent-related design history is preserved separately. This runtime page does not
              assert filing status, novelty over prior art, compliance, or authorization.
            </p>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div className="upper" style={{ marginBottom: 10 }}>Inventor</div>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>R. Blake</div>
            <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>
              Repository license, confidentiality, and distribution controls govern use of this
              code; protocol tests do not determine patent or legal status.
            </p>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div className="upper" style={{ marginBottom: 10 }}>Version history</div>
            <div className="col" style={{ gap: 8 }}>
              {[
                { v: '0.1.x', date: '2026-07-15', note: 'Beta hardening: atomic lifecycle commit, replacement, and claim corrections' },
                { v: 'wire 1', date: '2026-04-09', note: 'Initial wire format and segment derivation design' },
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
            { label: 'Server-held state', desc: 'The server retains authoritative counters, lifecycle status, and validation state. Layout is not treated as secret.' },
            { label: 'Independent schedules', desc: 'Time-window and counter-based values are derived independently from one provisioned shared secret.' },
            { label: 'Integrity-first reject', desc: 'A truncated HMAC tag is checked before per-segment validation. It is not a digital signature.' },
            { label: 'Atomic validation commit', desc: 'All matched counters and lifecycle usage commit together. Failed preconditions do not partially consume state.' },
            { label: 'Anomaly telemetry', desc: 'Per-segment results can feed an anomaly engine. A score is telemetry, not proof that a request is safe or malicious.' },
            { label: 'BPC composability', desc: 'Require both authorized BPC pair-key possession and TSK shared-secret validation, with mandatory principal matching.' },
          ].map(p => (
            <div key={p.label} style={{ padding: '14px 16px', borderRadius: 10,
              background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>{p.label}</div>
              <p style={{ fontSize: 12, lineHeight: 1.5 }}>{p.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Industry verticals */}
      <div>
        <div className="upper" style={{ color: 'var(--dim)', marginBottom: 16 }}>Deployment evaluation boundaries</div>
        <div className="g2" style={{ gap: 16 }}>
          <div className="card" style={{ padding: 20, borderLeft: '3px solid #3dd68c' }}>
            <div className="upper" style={{ color: '#3dd68c', marginBottom: 10 }}>Healthcare evaluation</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>A deployment requires separate safeguards and assessment</div>
            <p style={{ fontSize: 12.5, lineHeight: 1.6 }}>
              TSK does not establish HIPAA compliance, device identity, PHI authorization, retention, or breach controls. Those must be implemented and assessed in the operating system.
            </p>
            <div className="row" style={{ gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
              {['No compliance claim', 'No device identity', 'Assessment required'].map(t => (
                <span key={t} className="mono" style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'var(--bg-2)', color: 'var(--muted)' }}>{t}</span>
              ))}
            </div>
          </div>
          <div className="card" style={{ padding: 20, borderLeft: '3px solid var(--primary)' }}>
            <div className="upper" style={{ color: 'var(--primary)', marginBottom: 10 }}>Financial-services evaluation</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Payment APIs, open banking, fraud-sensitive data access</div>
            <p style={{ fontSize: 12.5, lineHeight: 1.6 }}>
              Atomic counter consumption addresses tested duplicate-use cases. It does not establish PCI DSS, SOC 2, fraud prevention, transaction authorization, or protection after shared-secret compromise.
            </p>
            <div className="row" style={{ gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
              {['Candidate component only', 'No audit opinion', 'Application policy required'].map(t => (
                <span key={t} className="mono" style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'var(--bg-2)', color: 'var(--muted)' }}>{t}</span>
              ))}
            </div>
          </div>
          <div className="card" style={{ padding: 20, borderLeft: '3px solid var(--warning)' }}>
            <div className="upper" style={{ color: 'var(--warning)', marginBottom: 10 }}>Government evaluation</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Federal agency APIs, CUI access, contractor credential management</div>
            <p style={{ fontSize: 12.5, lineHeight: 1.6 }}>
              Named tests may support a future assessed system, but this repository has no ATO, FedRAMP authorization, DoD Impact Level authorization, or qualified-assessor control determination.
            </p>
            <div className="row" style={{ gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
              {['No ATO', 'No Impact Level claim', 'Preliminary mappings only'].map(t => (
                <span key={t} className="mono" style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'var(--bg-2)', color: 'var(--muted)' }}>{t}</span>
              ))}
            </div>
          </div>
          <div className="card" style={{ padding: 20, borderLeft: '3px solid var(--dim)' }}>
            <div className="upper" style={{ color: 'var(--dim)', marginBottom: 10 }}>Enterprise evaluation</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>B2B API platforms, multi-tenant SaaS, developer ecosystems</div>
            <p style={{ fontSize: 12.5, lineHeight: 1.6 }}>
              Each client receives distinct secret material, but tenant isolation, audit evidence, recovery, key custody, and authorization remain deployment responsibilities. The BPC bridge adds an identity-match check, not an audit trail.
            </p>
            <div className="row" style={{ gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
              {['Tenant isolation required', 'Evidence required', 'External assessment required'].map(t => (
                <span key={t} className="mono" style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'var(--bg-2)', color: 'var(--muted)' }}>{t}</span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Self-service integration */}
      <div className="card">
        <h3 style={{ marginBottom: 6 }}>Reference integration</h3>
        <p className="muted" style={{ fontSize: 13, marginBottom: 20 }}>Three steps from zero to TSK-verified requests.</p>
        <div className="g3" style={{ gap: 12, marginBottom: 16 }}>
          {[
            { n: '1', title: 'Install', code: 'npm i @tsk/server @tsk/core' },
            { n: '2', title: 'Server', code: 'createTSKServer() + verifyTSKRequest() wraps any endpoint.' },
            { n: '3', title: 'Provision', code: 'Protect the endpoint, store server state, and deliver secret + metadata through approved channels.' },
          ].map(s => (
            <div key={s.n} style={{ padding: 16, borderRadius: 10, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
              <div className="row" style={{ gap: 8, marginBottom: 8 }}>
                <span style={{ width: 22, height: 22, borderRadius: '50%', background: 'var(--primary)', color: 'var(--bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, flexShrink: 0 }}>{s.n}</span>
                <span style={{ fontSize: 13, fontWeight: 600 }}>{s.title}</span>
              </div>
              <code className="mono" style={{ fontSize: 11, color: 'var(--muted)', lineHeight: 1.5 }}>{s.code}</code>
            </div>
          ))}
        </div>
        <div style={{ padding: '12px 14px', borderRadius: 8, background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12, lineHeight: 1.6 }}>
          <strong style={{ color: 'var(--text)' }}>Error boundary:</strong> The verifier returns structured internal results. HTTP status mapping, response redaction, audit emission, and operator alerting are adapter responsibilities.
        </div>
      </div>

      {/* Bond architecture */}
      <div className="card" style={{ border: '1px solid var(--warning)' }}>
        <div className="ch" style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)' }}>
          <div>
            <h3 style={{ marginBottom: 4 }}>Bond Architecture — how the ID is stored and linked</h3>
            <p className="muted" style={{ fontSize: 13 }}>A TSK credential combines client ID, shared secret, segment metadata, counters, and lifecycle state. Layout is not treated as secret.</p>
          </div>
          <Pill tone="warn">SERVER-HELD STATE</Pill>
        </div>

        <div className="cb">
          <div className="g3" style={{ gap: 12, marginBottom: 16 }}>
            {[
              {
                label: 'clientId',
                color: 'var(--warning)',
                body: 'Issued at provisioning. Stored by the client. Sent in every request as X-TSK-Client-ID. Server maps it to the full TumblerMap including positions.',
                server: 'tsk-maps.json \u2192 TumblerMap',
                client: 'provision payload \u2014 clientId field',
              },
              {
                label: 'sharedSecret',
                color: 'var(--warning)',
                body: 'Hex string. Both server and client store it. Used as HMAC-SHA256 key for ALL segment derivation \u2014 static, TOTP, HOTP, checksum. Changing it invalidates the entire tumbler.',
                server: 'TumblerMap.sharedSecret',
                client: 'deployment secret storage \u2014 separate from provision payload',
              },
              {
                label: 'Segment boundaries',
                color: 'var(--danger)',
                body: 'The server stores absolute [start, end) positions. The client receives ordered lengths and can reconstruct equivalent boundaries cumulatively. They are not an authentication factor.',
                server: 'TumblerMap.segments[].position',
                client: 'clientSegments[].segmentLength in positional order',
              },
              {
                label: 'HOTP counter (atomic CAS)',
                color: 'var(--primary)',
                body: 'Advances by compare-and-swap on every successful HOTP validation. A concurrent replay of the same key is detected when the server finds the counter has already advanced. Client must track its counter and stay synchronized.',
                server: 'TumblerMap.segments[].counter \u2014 updated atomically',
                client: 'local counter, reset on re-provisioning',
              },
            ].map(c => (
              <div key={c.label} style={{ padding: 14, borderRadius: 8, background: 'var(--bg-2)', border: '1px solid var(--border)' }}>
                <div className="row" style={{ gap: 8, marginBottom: 8, alignItems: 'center' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: c.color, flexShrink: 0 }} />
                  <span style={{ fontSize: 12, fontWeight: 700 }}>{c.label}</span>
                </div>
                <p style={{ fontSize: 12, lineHeight: 1.55, marginBottom: 8 }}>{c.body}</p>
                <div className="mono" style={{ fontSize: 10, color: 'var(--dim)', lineHeight: 1.7 }}>
                  <div>SERVER: {c.server}</div>
                  <div>CLIENT: {c.client}</div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            <div style={{ padding: 14, borderRadius: 8, background: 'color-mix(in oklab, var(--success) 8%, transparent)', border: '1px solid color-mix(in oklab, var(--success) 25%, transparent)' }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--success)', marginBottom: 8 }}>Does NOT break the bond</div>
              <ul style={{ margin: 0, paddingLeft: 14, fontSize: 12, color: 'var(--muted)', lineHeight: 1.8 }}>
                <li>Server restart (with file store — tsk-maps.json persists)</li>
                <li>Changing what endpoint the key is used against</li>
                <li>New TOTP windows — client auto-derives new values</li>
                <li>Server-side counter advance (client stays in sync)</li>
              </ul>
            </div>
            <div style={{ padding: 14, borderRadius: 8, background: 'color-mix(in oklab, var(--danger) 8%, transparent)', border: '1px solid color-mix(in oklab, var(--danger) 25%, transparent)' }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--danger)', marginBottom: 8 }}>Breaks the bond</div>
              <ul style={{ margin: 0, paddingLeft: 14, fontSize: 12, color: 'var(--muted)', lineHeight: 1.8 }}>
                <li>Server store deleted (tsk-maps.json lost, no backup)</li>
                <li>sharedSecret lost on client side — re-provision required</li>
                <li>Explicit revocation: <code>POST /tsk/revoke</code></li>
                <li>HOTP counter desync beyond lookahead window</li>
              </ul>
            </div>
          </div>

          <div style={{ padding: 12, borderRadius: 8, background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12, lineHeight: 1.6 }}>
            <strong style={{ color: 'var(--text)' }}>Universal scope:</strong>{' '}
            <code className="mono">verifyTSKRequest()</code> authenticates the provisioned TSK client identifier. Pair it with BPC to require both protocol checks and an explicit principal binding. Downstream authorization remains required.
          </div>
        </div>
      </div>

      {/* Three-site architecture */}
      <div className="card">
        <h3 style={{ marginBottom: 4 }}>Three demo deployments</h3>
        <p className="muted" style={{ fontSize: 13, marginBottom: 16 }}>
          Demo deployments share the protocol implementation; they are not production or authorization evidence.
        </p>
        <div className="g3">
          {[
            {
              port: ':3200', label: 'TSK Standalone', current: true,
              desc: 'Layers 6 + 7. Segment derivation plus atomic counter and lifecycle state.',
              tone: 'primary',
            },
            {
              port: ':3100', label: 'Composed Verifier',
              desc: 'BPC + TSK checks with principal identity binding.',
              tone: 'warn', href: 'http://localhost:3100',
            },
            {
              port: ':3101', label: 'BPC Standalone',
              desc: 'Layers 1–5. Authorized BPC pair-key verification and behavioral telemetry.',
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
            TSK is pre-release. For licensing inquiries, integration
            partnerships, or early access, reach out directly.
          </p>
        </div>
        <div className="col" style={{ gap: 10, alignItems: 'flex-start' }}>
          <button className="btn primary" onClick={handleRequestAccess}
            style={{ fontSize: 14 }}>
            Request access
          </button>
          <button className="btn sm ghost" onClick={() => goto('stack')}>
            View the composed verifier →
          </button>
        </div>
      </div>

      {/* Legal footer */}
      <div style={{ padding: '16px 0', borderTop: '1px solid var(--border)' }}>
        <p className="mono" style={{ fontSize: 11, color: 'var(--dim)', lineHeight: 1.7 }}>
          TSK beta reference implementation · Wire protocol 1 · © 2026 R. Blake.
          Patent and distribution status must be established by the applicable legal records and repository license.
        </p>
      </div>
    </div>
  );
}

window.ScreenAbout = ScreenAbout;
