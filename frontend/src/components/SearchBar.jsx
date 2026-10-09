import { useState } from 'react'
import { Search, Globe, Hash, Server, Link2, X } from 'lucide-react'

const EXAMPLES = [
  { label: 'Public IP', value: '8.8.8.8', icon: Server, color: '#38bdf8' },
  { label: 'Domain', value: 'google.com', icon: Globe, color: '#34d399' },
  { label: 'Malware Hash', value: '44d88612fea8a8f36de82e1278abb02f', icon: Hash, color: '#f43f5e' },
  { label: 'Website URL', value: 'https://example.com', icon: Link2, color: '#a78bfa' },
]

export default function SearchBar({ onSearch, loading }) {
  const [indicator, setIndicator] = useState('')
  const [type, setType] = useState('auto')

  const handleSubmit = (e) => {
    e.preventDefault()
    const trimmed = indicator.trim()
    if (!trimmed) return
    onSearch(trimmed, type === 'auto' ? null : type)
  }

  return (
    <div className="search-section">
      <div className="search-container">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <h3>
            <Search size={18} style={{ color: 'var(--cyan)' }} />
            Threat Indicator Search
          </h3>
          <span style={{ fontSize: '.74rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ padding: '2px 6px', background: 'rgba(255,255,255,0.06)', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)', fontFamily: 'var(--font-mono)', fontSize: '.68rem' }}>Enter ↵</span> to analyze
          </span>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="search-row">
            <div className="search-input-wrap">
              <Search size={16} className="icon-prefix" />
              <input
                id="indicator-input"
                type="text"
                placeholder="Enter an IP address, website domain, URL, or file hash…"
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                autoComplete="off"
                spellCheck="false"
              />
              {indicator && (
                <button
                  type="button"
                  onClick={() => setIndicator('')}
                  style={{
                    position: 'absolute',
                    right: '12px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    padding: '2px',
                  }}
                  title="Clear input"
                >
                  <X size={14} />
                </button>
              )}
            </div>
            <select
              className="search-type-select"
              value={type}
              onChange={(e) => setType(e.target.value)}
              id="indicator-type"
            >
              <option value="auto">Auto-detect Type</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain Name</option>
              <option value="url">Website URL</option>
              <option value="hash">File Hash (MD5 / SHA256)</option>
            </select>
            <button
              type="submit"
              className="search-btn"
              disabled={loading || !indicator.trim()}
              id="search-submit"
            >
              {loading ? (
                <>
                  <span className="spinner-sm" /> Scanning Feeds…
                </>
              ) : (
                <>
                  <Search size={16} /> Analyze Threat
                </>
              )}
            </button>
          </div>
        </form>
        <div className="search-hints">
          <span style={{ fontSize: '.72rem', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', marginRight: '6px', fontWeight: 500 }}>
            Quick Examples:
          </span>
          {EXAMPLES.map((ex) => {
            const IconComponent = ex.icon
            return (
              <span
                key={ex.value}
                className="search-hint-tag"
                onClick={() => {
                  setIndicator(ex.value)
                  setType('auto')
                }}
              >
                <IconComponent size={12} style={{ color: ex.color, marginRight: '4px' }} />
                <strong>{ex.label}:</strong> {ex.value}
              </span>
            )
          })}
        </div>
      </div>
    </div>
  )
}
