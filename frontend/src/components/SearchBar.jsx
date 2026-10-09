import { useState } from 'react'
import { Search } from 'lucide-react'

const EXAMPLES = [
  { label: 'IP', value: '8.8.8.8' },
  { label: 'Domain', value: 'google.com' },
  { label: 'Hash', value: '44d88612fea8a8f36de82e1278abb02f' },
  { label: 'URL', value: 'https://example.com' },
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
        <h3>🔍 Indicator Lookup</h3>
        <form onSubmit={handleSubmit}>
          <div className="search-row">
            <div className="search-input-wrap">
              <Search size={16} className="icon-prefix" />
              <input
                id="indicator-input"
                type="text"
                placeholder="Enter IP, domain, URL, or file hash…"
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                autoComplete="off"
                spellCheck="false"
              />
            </div>
            <select
              className="search-type-select"
              value={type}
              onChange={(e) => setType(e.target.value)}
              id="indicator-type"
            >
              <option value="auto">Auto-detect</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash">File Hash</option>
            </select>
            <button
              type="submit"
              className="search-btn"
              disabled={loading || !indicator.trim()}
              id="search-submit"
            >
              {loading ? (
                <>
                  <span className="spinner-sm" /> Scanning…
                </>
              ) : (
                <>
                  <Search size={16} /> Analyze
                </>
              )}
            </button>
          </div>
        </form>
        <div className="search-hints">
          {EXAMPLES.map((ex) => (
            <span
              key={ex.value}
              className="search-hint-tag"
              onClick={() => {
                setIndicator(ex.value)
                setType('auto')
              }}
            >
              {ex.label}: {ex.value}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
