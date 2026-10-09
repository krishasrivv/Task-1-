import { useState, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import StatsCards from './components/StatsCards'
import SearchBar from './components/SearchBar'
import VirusTotalReport from './components/VirusTotalReport'
import AlienVaultReport from './components/AlienVaultReport'
import DetectionCharts from './components/DetectionCharts'
import SourceStatus from './components/SourceStatus'
import Chatbot from './components/Chatbot'

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [activeView, setActiveView] = useState('dashboard')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [lookupResult, setLookupResult] = useState(null)
  const [healthData, setHealthData] = useState(null)

  const handleLookup = useCallback(async (indicator, type) => {
    setLoading(true)
    setError(null)
    setLookupResult(null)
    try {
      const res = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator, type: type || undefined }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || `Server returned ${res.status}`)
      } else {
        setLookupResult(data)
      }
    } catch (err) {
      setError('Network error — is the backend running on port 5000?')
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchHealth = useCallback(async () => {
    try {
      const res = await fetch('/api/health')
      const data = await res.json()
      setHealthData(data)
    } catch {
      setHealthData(null)
    }
  }, [])

  // Fetch health on mount
  useState(() => { fetchHealth() })

  const vtData = lookupResult?.virustotal
  const otxData = lookupResult?.alienvault_otx

  return (
    <div className="app-layout">
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <Sidebar
        open={sidebarOpen}
        activeView={activeView}
        onNavigate={(v) => { setActiveView(v); setSidebarOpen(false); }}
        healthData={healthData}
      />

      <div className="main-content">
        <Header
          onMenuToggle={() => setSidebarOpen(o => !o)}
          onRefreshHealth={fetchHealth}
        />

        <div className="page-body">
          {activeView === 'dashboard' && (
            <>
              <StatsCards vtData={vtData} otxData={otxData} />
              <SearchBar onSearch={handleLookup} loading={loading} />

              {error && (
                <div className="error-banner">
                  <span>⚠</span> {error}
                </div>
              )}

              {loading && (
                <div className="loading-overlay">
                  <div className="spinner" />
                  <p className="loading-text">Querying threat intelligence sources…</p>
                </div>
              )}

              {lookupResult && !loading && (
                <>
                  <div className="reports-grid">
                    <VirusTotalReport data={vtData} />
                    <AlienVaultReport data={otxData} />
                  </div>
                  <DetectionCharts vtData={vtData} otxData={otxData} />
                </>
              )}

              <SourceStatus healthData={healthData} />
            </>
          )}

          {activeView === 'chat' && (
            <Chatbot lookupResult={lookupResult} />
          )}
        </div>
      </div>
    </div>
  )
}

export default App
