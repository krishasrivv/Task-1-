import {
  Shield,
  Search,
  LayoutDashboard,
  MessageSquare,
  Activity,
  Settings,
  BookOpen,
} from 'lucide-react'

export default function Sidebar({ open, activeView, onNavigate, healthData }) {
  const sources = healthData?.sources || {}

  const statusDot = (key) => {
    const val = sources[key]
    if (val === 'configured') return 'green'
    if (val === 'not configured') return 'red'
    return 'orange'
  }

  return (
    <aside className={`sidebar ${open ? 'open' : ''}`}>
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Shield size={22} />
        </div>
        <div>
          <h1>ThreatIntel AI</h1>
          <span>Threat Intelligence</span>
        </div>
      </div>

      {/* Navigation */}
      <p className="sidebar-section-label">Main</p>
      <ul className="sidebar-nav">
        <li>
          <button
            className={activeView === 'dashboard' ? 'active' : ''}
            onClick={() => onNavigate('dashboard')}
          >
            <LayoutDashboard size={18} /> Dashboard
          </button>
        </li>
        <li>
          <button
            className={activeView === 'chat' ? 'active' : ''}
            onClick={() => onNavigate('chat')}
          >
            <MessageSquare size={18} /> AI Assistant
          </button>
        </li>
      </ul>

      <p className="sidebar-section-label">Resources</p>
      <ul className="sidebar-nav">
        <li>
          <a href="https://docs.virustotal.com/reference/overview" target="_blank" rel="noreferrer">
            <BookOpen size={18} /> VT Docs
          </a>
        </li>
        <li>
          <a href="https://otx.alienvault.com/api" target="_blank" rel="noreferrer">
            <BookOpen size={18} /> OTX Docs
          </a>
        </li>
      </ul>

      {/* Footer – source status */}
      <div className="sidebar-footer">
        <p className="sidebar-section-label" style={{ padding: 0, marginBottom: '8px' }}>
          Source Status
        </p>
        <p>
          <span className={`source-dot ${statusDot('virustotal')}`} />
          VirusTotal
        </p>
        <p>
          <span className={`source-dot ${statusDot('alienvault_otx')}`} />
          AlienVault OTX
        </p>
        <p>
          <span className={`source-dot ${statusDot('nvidia_ai')}`} />
          NVIDIA AI
        </p>
      </div>
    </aside>
  )
}
