import { Radar, ShieldAlert, Globe, Network, Award, Info } from 'lucide-react'

export default function AlienVaultReport({ data }) {
  if (!data) return null

  const badge = data.found
    ? 'badge-found'
    : data.error
    ? 'badge-error'
    : 'badge-not-found'

  const badgeText = data.found ? 'Report Available' : data.error ? 'Scan Error' : 'No Threat Records'

  return (
    <div className="report-panel">
      <div className="report-panel-header">
        <h3>
          <Radar size={18} style={{ color: 'var(--cyan)' }} />
          AlienVault OTX Community Intelligence
        </h3>
        <span className={`badge ${badge}`}>{badgeText}</span>
      </div>

      {data.error && !data.found && (
        <div className="error-banner" style={{ marginBottom: '12px' }}>
          <span>⚠</span> {data.error}
        </div>
      )}

      {data.found && (
        <>
          <div className="report-field">
            <span className="field-label">Target Indicator</span>
            <span className="field-value">{data.indicator}</span>
          </div>
          <div className="report-field">
            <span className="field-label">Category</span>
            <span className="field-value" style={{ textTransform: 'uppercase' }}>
              {data.indicator_type === 'ip' ? 'IP Address' : data.indicator_type === 'hash' ? 'File Hash' : data.indicator_type === 'domain' ? 'Domain Name' : data.indicator_type}
            </span>
          </div>
          <div className="report-field">
            <span className="field-label">Threat Alerts (Pulses)</span>
            <span className={`field-value ${data.pulse_count > 0 ? 'warn' : 'safe'}`}>
              {data.pulse_count} {data.pulse_count === 1 ? 'alert' : 'alerts'} reported by security researchers
            </span>
          </div>

          {data.country && data.country !== 'N/A' && (
            <div className="report-field">
              <span className="field-label">Hosting Country</span>
              <span className="field-value">{data.country}</span>
            </div>
          )}

          {data.asn && (
            <div className="report-field">
              <span className="field-label">Network Owner (ASN)</span>
              <span className="field-value">{data.asn}</span>
            </div>
          )}

          {data.reputation !== null && data.reputation !== undefined && (
            <div className="report-field">
              <span className="field-label">Trust Score</span>
              <span className="field-value">{data.reputation}</span>
            </div>
          )}

          {/* Validation tags if present */}
          {data.validation && data.validation.length > 0 && (
            <div className="report-field" style={{ flexDirection: 'column', gap: '6px' }}>
              <span className="field-label">Community Validations</span>
              <div className="pulse-tags">
                {data.validation.map((v, i) => (
                  <span key={i} className="pulse-tag" style={{ background: 'rgba(59,130,246,.12)', color: '#93c5fd' }}>
                    {v.name || v.message || String(v)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Pulses */}
          {data.pulses && data.pulses.length > 0 ? (
            <div style={{ marginTop: '14px' }}>
              <p style={{ fontSize: '.82rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px' }}>
                Active Threat Alerts ({data.pulses.length})
              </p>
              <ul className="pulse-list">
                {data.pulses.slice(0, 5).map((p, i) => (
                  <li key={i} className="pulse-item">
                    <h4>{p.name || 'Security Alert'}</h4>
                    {p.description && <p>{p.description}</p>}
                    {p.adversary && (
                      <p style={{ color: 'var(--red)', fontSize: '.75rem', marginTop: '4px' }}>
                        Known Threat Actor: {p.adversary}
                      </p>
                    )}
                    {p.tags && p.tags.length > 0 && (
                      <div className="pulse-tags">
                        {p.tags.map((t, j) => (
                          <span key={j} className="pulse-tag">{t}</span>
                        ))}
                      </div>
                    )}
                    {p.attack_ids && p.attack_ids.length > 0 && (
                      <div className="pulse-tags" style={{ marginTop: '4px' }}>
                        {p.attack_ids.map((a, k) => (
                          <span key={k} className="pulse-tag" style={{ background: 'rgba(239,68,68,.12)', color: 'var(--red)' }}>
                            Attack Technique: {a}
                          </span>
                        ))}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div style={{ marginTop: '12px', padding: '10px 14px', background: 'var(--bg-input)', borderRadius: '6px', fontSize: '.8rem', color: 'var(--text-muted)' }}>
              No active threat pulses reported for this indicator in AlienVault OTX.
            </div>
          )}
        </>
      )}
    </div>
  )
}
