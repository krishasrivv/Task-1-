import { ShieldAlert, ShieldCheck, Search, Activity, Radar, Bug } from 'lucide-react'

export default function StatsCards({ vtData, otxData }) {
  const stats = vtData?.stats || {}
  const malicious = stats.malicious || 0
  const suspicious = stats.suspicious || 0
  const harmless = stats.harmless || 0
  const undetected = stats.undetected || 0
  const totalEngines = malicious + suspicious + harmless + undetected + (stats.timeout || 0)
  const pulseCount = otxData?.pulse_count || 0
  const vtFound = vtData?.found ? 'Available' : 'None'

  return (
    <div className="stats-grid">
      <div className="stat-card" style={{ animationDelay: '0s' }}>
        <div className="stat-card-icon red">
          <ShieldAlert size={24} />
        </div>
        <div className="stat-card-content">
          <h3>Malicious</h3>
          <div className="stat-value">{malicious}</div>
          <div className="stat-sub">confirmed threat flags</div>
        </div>
      </div>

      <div className="stat-card" style={{ animationDelay: '.05s' }}>
        <div className="stat-card-icon orange">
          <Bug size={24} />
        </div>
        <div className="stat-card-content">
          <h3>Suspicious</h3>
          <div className="stat-value">{suspicious}</div>
          <div className="stat-sub">risky behavior flags</div>
        </div>
      </div>

      <div className="stat-card" style={{ animationDelay: '.1s' }}>
        <div className="stat-card-icon green">
          <ShieldCheck size={24} />
        </div>
        <div className="stat-card-content">
          <h3>Harmless</h3>
          <div className="stat-value">{harmless}</div>
          <div className="stat-sub">clean / benign scans</div>
        </div>
      </div>

      <div className="stat-card" style={{ animationDelay: '.15s' }}>
        <div className="stat-card-icon blue">
          <Activity size={24} />
        </div>
        <div className="stat-card-content">
          <h3>Scanners Checked</h3>
          <div className="stat-value">{totalEngines}</div>
          <div className="stat-sub">total security engines</div>
        </div>
      </div>

      <div className="stat-card" style={{ animationDelay: '.2s' }}>
        <div className="stat-card-icon purple">
          <Radar size={24} />
        </div>
        <div className="stat-card-content">
          <h3>Community Alerts</h3>
          <div className="stat-value">{pulseCount}</div>
          <div className="stat-sub">OTX threat pulses</div>
        </div>
      </div>

      <div className="stat-card" style={{ animationDelay: '.25s' }}>
        <div className="stat-card-icon cyan">
          <Search size={24} />
        </div>
        <div className="stat-card-content">
          <h3>Scanner Record</h3>
          <div className="stat-value">{vtFound}</div>
          <div className="stat-sub">VirusTotal database</div>
        </div>
      </div>
    </div>
  )
}
