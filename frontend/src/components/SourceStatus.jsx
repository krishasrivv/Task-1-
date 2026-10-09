import { Wifi, WifiOff, AlertTriangle } from 'lucide-react'

const SOURCES = [
  { key: 'virustotal', name: 'VirusTotal', desc: 'Malware & URL scanner' },
  { key: 'alienvault_otx', name: 'AlienVault OTX', desc: 'Open threat exchange' },
  { key: 'nvidia_ai', name: 'NVIDIA AI', desc: 'LLM chat analysis' },
]

export default function SourceStatus({ healthData }) {
  const sources = healthData?.sources || {}

  const statusInfo = (key) => {
    const val = sources[key]
    if (val === 'configured') return { cls: 'online', text: 'Configured', Icon: Wifi }
    if (val === 'not configured') return { cls: 'offline', text: 'Not Configured', Icon: WifiOff }
    return { cls: 'warning', text: 'Unknown', Icon: AlertTriangle }
  }

  return (
    <div>
      <h3 style={{
        fontSize: '.85rem', fontWeight: 600, color: 'var(--text-muted)',
        textTransform: 'uppercase', letterSpacing: '.5px', marginBottom: '12px',
      }}>
        Intelligence Sources
      </h3>
      <div className="source-status-grid">
        {SOURCES.map(s => {
          const info = statusInfo(s.key)
          return (
            <div key={s.key} className="source-status-card">
              <div className={`status-indicator ${info.cls}`} />
              <div className="source-info">
                <h4>{s.name}</h4>
                <p>{s.desc} · {info.text}</p>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
