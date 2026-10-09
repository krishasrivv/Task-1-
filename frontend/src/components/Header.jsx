import { Menu, RefreshCw, Shield } from 'lucide-react'

export default function Header({ onMenuToggle, onRefreshHealth }) {
  const now = new Date()
  const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  const dateStr = now.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })

  return (
    <header className="dashboard-header">
      <div className="header-left">
        <button className="menu-toggle" onClick={onMenuToggle} aria-label="Toggle menu">
          <Menu size={20} />
        </button>
        <div>
          <h2>Threat Intelligence Dashboard</h2>
          <p>{dateStr} · {timeStr}</p>
        </div>
      </div>
      <div className="header-right">
        <button
          className="search-btn"
          onClick={onRefreshHealth}
          title="Refresh source status"
          style={{ padding: '8px 12px' }}
        >
          <RefreshCw size={16} />
        </button>
      </div>
    </header>
  )
}
