import { Shield, ExternalLink } from 'lucide-react'

export default function VirusTotalReport({ data }) {
  if (!data) return null

  const badge = data.found
    ? 'badge-found'
    : data.error
    ? 'badge-error'
    : 'badge-not-found'

  const badgeText = data.found ? 'Found' : data.error ? 'Error' : 'Not Found'

  const stats = data.stats || {}
  const malicious = stats.malicious || 0
  const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0) + (stats.timeout || 0)

  const dangerClass = malicious > 5 ? 'danger' : malicious > 0 ? 'warn' : 'safe'

  return (
    <div className="report-panel">
      <div className="report-panel-header">
        <h3>
          <Shield size={18} style={{ color: 'var(--accent)' }} />
          VirusTotal Report
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
            <span className="field-label">Detection</span>
            <span className={`field-value ${dangerClass}`}>
              {malicious} / {total} engines
            </span>
          </div>
          <div className="report-field">
            <span className="field-label">Suspicious</span>
            <span className="field-value">{stats.suspicious || 0}</span>
          </div>
          <div className="report-field">
            <span className="field-label">Harmless</span>
            <span className="field-value safe">{stats.harmless || 0}</span>
          </div>
          <div className="report-field">
            <span className="field-label">Undetected</span>
            <span className="field-value">{stats.undetected || 0}</span>
          </div>

          {data.reputation !== null && data.reputation !== undefined && (
            <div className="report-field">
              <span className="field-label">Reputation</span>
              <span className={`field-value ${data.reputation < 0 ? 'danger' : 'safe'}`}>
                {data.reputation}
              </span>
            </div>
          )}

          {/* IP-specific */}
          {data.country && (
            <div className="report-field">
              <span className="field-label">Country</span>
              <span className="field-value">{data.country}</span>
            </div>
          )}
          {data.as_owner && (
            <div className="report-field">
              <span className="field-label">AS Owner</span>
              <span className="field-value">{data.as_owner}</span>
            </div>
          )}
          {data.network && (
            <div className="report-field">
              <span className="field-label">Network</span>
              <span className="field-value">{data.network}</span>
            </div>
          )}

          {/* Domain-specific */}
          {data.registrar && data.indicator_type === 'domain' && (
            <div className="report-field">
              <span className="field-label">Registrar</span>
              <span className="field-value">{data.registrar}</span>
            </div>
          )}

          {/* Hash-specific */}
          {data.meaningful_name && data.indicator_type === 'hash' && (
            <div className="report-field">
              <span className="field-label">Name</span>
              <span className="field-value">{data.meaningful_name}</span>
            </div>
          )}
          {data.type_description && data.indicator_type === 'hash' && (
            <div className="report-field">
              <span className="field-label">File Type</span>
              <span className="field-value">{data.type_description}</span>
            </div>
          )}
          {data.popular_threat_label && (
            <div className="report-field">
              <span className="field-label">Threat Label</span>
              <span className="field-value danger">{data.popular_threat_label}</span>
            </div>
          )}
          {data.size && (
            <div className="report-field">
              <span className="field-label">Size</span>
              <span className="field-value">{(data.size / 1024).toFixed(1)} KB</span>
            </div>
          )}

          {/* Tags */}
          {data.tags && data.tags.length > 0 && (
            <div className="report-field" style={{ flexDirection: 'column', gap: '6px' }}>
              <span className="field-label">Tags</span>
              <div className="pulse-tags">
                {data.tags.map((t, i) => (
                  <span key={i} className="pulse-tag">{t}</span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
