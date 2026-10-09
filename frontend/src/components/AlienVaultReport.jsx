import { Radar } from 'lucide-react'

export default function AlienVaultReport({ data }) {
  if (!data) return null

  const badge = data.found
    ? 'badge-found'
    : data.error
    ? 'badge-error'
    : 'badge-not-found'

  const badgeText = data.found ? 'Found' : data.error ? 'Error' : 'Not Found'

  return (
    <div className="report-panel">
      <div className="report-panel-header">
        <h3>
          <Radar size={18} style={{ color: 'var(--cyan)' }} />
          AlienVault OTX Report
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
            <span className="field-label">Indicator</span>
            <span className="field-value">{data.indicator}</span>
          </div>
          <div className="report-field">
            <span className="field-label">Type</span>
            <span className="field-value">{data.indicator_type}</span>
          </div>
          <div className="report-field">
            <span className="field-label">Pulse Count</span>
            <span className={`field-value ${data.pulse_count > 0 ? 'warn' : 'safe'}`}>
              {data.pulse_count}
            </span>
          </div>

          {data.country && data.country !== 'N/A' && (
            <div className="report-field">
              <span className="field-label">Country</span>
              <span className="field-value">{data.country}</span>
            </div>
          )}

          {data.asn && (
            <div className="report-field">
              <span className="field-label">ASN</span>
              <span className="field-value">{data.asn}</span>
            </div>
          )}

          {data.reputation !== null && data.reputation !== undefined && (
            <div className="report-field">
              <span className="field-label">Reputation</span>
              <span className="field-value">{data.reputation}</span>
            </div>
          )}

          {/* Pulses */}
          {data.pulses && data.pulses.length > 0 && (
            <div style={{ marginTop: '12px' }}>
              <p style={{ fontSize: '.82rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
                Threat Pulses ({data.pulses.length})
              </p>
              <ul className="pulse-list">
                {data.pulses.slice(0, 5).map((p, i) => (
                  <li key={i} className="pulse-item">
                    <h4>{p.name || 'Unnamed Pulse'}</h4>
                    {p.description && <p>{p.description}</p>}
                    {p.adversary && (
                      <p style={{ color: 'var(--red)', fontSize: '.75rem', marginTop: '4px' }}>
                        Adversary: {p.adversary}
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
                            {a}
                          </span>
                        ))}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  )
}
