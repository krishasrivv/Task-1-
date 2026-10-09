import { Shield, ExternalLink, AlertTriangle, CheckCircle, HelpCircle } from 'lucide-react'

export default function VirusTotalReport({ data }) {
  if (!data) return null

  const badge = data.found
    ? 'badge-found'
    : data.error
    ? 'badge-error'
    : 'badge-not-found'

  const badgeText = data.found ? 'Scan Available' : data.error ? 'Scan Error' : 'No Threat Records'

  const stats = data.stats || {}
  const malicious = stats.malicious || 0
  const suspicious = stats.suspicious || 0
  const harmless = stats.harmless || 0
  const undetected = stats.undetected || 0
  const total = malicious + suspicious + harmless + undetected + (stats.timeout || 0)

  const dangerClass = malicious > 5 ? 'danger' : malicious > 0 ? 'warn' : 'safe'

  return (
    <div className="report-panel">
      <div className="report-panel-header">
        <h3>
          <Shield size={18} style={{ color: 'var(--accent)' }} />
          VirusTotal Scanner Report
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
            <span className="field-label">Malicious Detections</span>
            <span className={`field-value ${dangerClass}`}>
              {malicious} of {total} security engines flagged this as dangerous
            </span>
          </div>
          <div className="report-field">
            <span className="field-label">Suspicious Activity</span>
            <span className="field-value">{suspicious} {suspicious === 1 ? 'engine flagged suspicious behavior' : 'engines flagged suspicious behavior'}</span>
          </div>
          <div className="report-field">
            <span className="field-label">Verified Clean / Harmless</span>
            <span className="field-value safe">{harmless} engines confirmed clean</span>
          </div>
          <div className="report-field">
            <span className="field-label">Undetected (No Prior Data)</span>
            <span className="field-value">{undetected} engines have no record</span>
          </div>

          {data.reputation !== null && data.reputation !== undefined && (
            <div className="report-field">
              <span className="field-label">Community Reputation</span>
              <span className={`field-value ${data.reputation < 0 ? 'danger' : 'safe'}`}>
                {data.reputation > 0 ? `+${data.reputation} (Positive)` : data.reputation < 0 ? `${data.reputation} (Negative)` : '0 (Neutral)'}
              </span>
            </div>
          )}

          {/* IP-specific */}
          {data.country && (
            <div className="report-field">
              <span className="field-label">Hosting Country</span>
              <span className="field-value">{data.country}</span>
            </div>
          )}
          {data.as_owner && (
            <div className="report-field">
              <span className="field-label">Internet Host / Provider</span>
              <span className="field-value">{data.as_owner}</span>
            </div>
          )}
          {data.network && (
            <div className="report-field">
              <span className="field-label">Network Range</span>
              <span className="field-value">{data.network}</span>
            </div>
          )}

          {/* Domain-specific */}
          {data.registrar && data.indicator_type === 'domain' && (
            <div className="report-field">
              <span className="field-label">Domain Registrar</span>
              <span className="field-value">{data.registrar}</span>
            </div>
          )}

          {/* Hash-specific */}
          {data.meaningful_name && data.indicator_type === 'hash' && (
            <div className="report-field">
              <span className="field-label">Identified File Name</span>
              <span className="field-value">{data.meaningful_name}</span>
            </div>
          )}
          {data.type_description && data.indicator_type === 'hash' && (
            <div className="report-field">
              <span className="field-label">File Format</span>
              <span className="field-value">{data.type_description}</span>
            </div>
          )}
          {data.popular_threat_label && (
            <div className="report-field">
              <span className="field-label">Threat Classification</span>
              <span className="field-value danger">{data.popular_threat_label}</span>
            </div>
          )}
          {data.size && (
            <div className="report-field">
              <span className="field-label">File Size</span>
              <span className="field-value">{(data.size / 1024).toFixed(1)} KB</span>
            </div>
          )}

          {/* Tags */}
          {data.tags && data.tags.length > 0 && (
            <div className="report-field" style={{ flexDirection: 'column', gap: '6px' }}>
              <span className="field-label">Security Tags</span>
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
