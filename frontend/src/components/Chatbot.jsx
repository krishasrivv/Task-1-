import { useState, useRef, useEffect } from 'react'
import ReactMarkdown from 'react-markdown'
import { Send, Bot, User, AlertCircle, Sparkles, RefreshCw, Download, Copy, Check, FileText } from 'lucide-react'

const SUGGESTIONS = [
  'Summarize threat level',
  'Explain detection counts',
  'Are there suspicious indicators?',
  'What actions should I take?',
]

export default function Chatbot({ lookupResult }) {
  const [messages, setMessages] = useState([
    {
      role: 'system',
      content: lookupResult
        ? 'Threat intelligence report loaded. Ask me anything to analyze this indicator.'
        : 'Search for an indicator (IP, domain, hash, or URL) first, then I can help you analyze the findings.',
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [copiedIndex, setCopiedIndex] = useState(null)
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  // Update system message when lookupResult changes
  useEffect(() => {
    if (lookupResult) {
      setMessages(prev => {
        const first = prev[0]
        if (first?.role === 'system') {
          return [
            {
              role: 'system',
              content: `Loaded report for \`${lookupResult.indicator}\` (${lookupResult.type?.toUpperCase() || 'Indicator'}). Ask me anything to analyze this indicator.`,
            },
            ...prev.slice(1),
          ]
        }
        return prev
      })
    }
  }, [lookupResult])

  const sendQuery = async (queryText) => {
    const text = (queryText || input).trim()
    if (!text || loading) return

    const userMsg = { role: 'user', content: text }
    setMessages(prev => [...prev, userMsg])
    if (!queryText) setInput('')
    setLoading(true)

    try {
      const contextPayload = lookupResult || {}
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, context: contextPayload }),
      })
      const data = await res.json()

      if (!res.ok || data.error) {
        setMessages(prev => [
          ...prev,
          {
            role: 'error',
            content: data.error || `Service returned HTTP ${res.status}.`,
          },
        ])
      } else {
        setMessages(prev => [...prev, { role: 'assistant', content: data.reply }])
      }
    } catch {
      setMessages(prev => [
        ...prev,
        {
          role: 'error',
          content: 'Network error — could not reach the backend AI service. Please ensure the Flask server is running.',
        },
      ])
    } finally {
      setLoading(false)
    }
  }

  const handleSend = () => sendQuery()

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const copyMessage = (content, index) => {
    navigator.clipboard.writeText(content)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  const downloadSingleMessage = (content, index) => {
    const indicator = lookupResult?.indicator || 'indicator'
    const cleanIndicator = indicator.replace(/[^a-zA-Z0-9.-]/g, '_')
    const filename = `threatintel-ai-analysis-${cleanIndicator}-${Date.now()}.md`
    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8;' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = filename
    link.click()
    URL.revokeObjectURL(link.href)
  }

  const downloadFullReport = () => {
    const indicator = lookupResult?.indicator || 'general-analysis'
    const cleanIndicator = indicator.replace(/[^a-zA-Z0-9.-]/g, '_')
    const now = new Date()
    const dateStr = now.toISOString().split('T')[0]

    let mdContent = `# ThreatIntel AI — Threat Intelligence Analysis Report\n`
    mdContent += `**Generated:** ${now.toLocaleString()}\n`
    if (lookupResult) {
      mdContent += `**Target Indicator:** \`${lookupResult.indicator}\`\n`
      mdContent += `**Indicator Type:** ${lookupResult.type?.toUpperCase() || 'N/A'}\n`
    }
    mdContent += `\n---\n\n## Analysis Transcript\n\n`

    messages.forEach((m) => {
      if (m.role === 'user') {
        mdContent += `### 👤 User Query\n${m.content}\n\n`
      } else if (m.role === 'assistant') {
        mdContent += `### 🤖 ThreatIntel AI Analysis\n${m.content}\n\n---\n\n`
      } else if (m.role === 'system') {
        mdContent += `> *System Context:* ${m.content}\n\n`
      }
    })

    const blob = new Blob([mdContent], { type: 'text/markdown;charset=utf-8;' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = `threatintel-report-${cleanIndicator}-${dateStr}.md`
    link.click()
    URL.revokeObjectURL(link.href)
  }

  const hasAssistantMessages = messages.some(m => m.role === 'assistant')

  return (
    <div className="chatbot-section">
      <div className="chatbot-panel">
        <div className="chatbot-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1 }}>
            <Bot size={20} style={{ color: 'var(--accent)' }} />
            <h3>ThreatIntel AI Assistant</h3>
            <span className="ai-badge">NVIDIA AI</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {hasAssistantMessages && (
              <button
                onClick={downloadFullReport}
                title="Download full analysis report as Markdown"
                style={{
                  background: 'rgba(59, 130, 246, 0.12)',
                  border: '1px solid rgba(59, 130, 246, 0.25)',
                  color: 'var(--accent-hover)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  fontSize: '.75rem',
                  fontWeight: 600,
                  padding: '5px 10px',
                  borderRadius: 'var(--radius-sm)',
                  transition: 'all .2s',
                }}
              >
                <Download size={13} /> Export Report
              </button>
            )}

            <button
              onClick={() => setMessages([
                {
                  role: 'system',
                  content: lookupResult
                    ? `Loaded report for \`${lookupResult.indicator}\` (${lookupResult.type?.toUpperCase() || 'Indicator'}). Ask me anything to analyze this indicator.`
                    : 'Search for an indicator (IP, domain, hash, or URL) first, then I can help you analyze the findings.',
                }
              ])}
              title="Reset conversation"
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                fontSize: '.75rem',
                padding: '5px 8px',
                borderRadius: 'var(--radius-sm)',
                transition: 'all .2s',
              }}
            >
              <RefreshCw size={13} /> Reset
            </button>
          </div>
        </div>

        <div className="chatbot-messages">
          {messages.map((msg, i) => (
            <div key={i} className={`chat-message ${msg.role}`}>
              {msg.role === 'user' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px', fontSize: '.72rem', opacity: .7 }}>
                  <User size={12} /> You
                </div>
              )}
              {msg.role === 'assistant' && (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px', fontSize: '.72rem', color: '#60a5fa' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Bot size={12} /> ThreatIntel AI
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      onClick={() => copyMessage(msg.content, i)}
                      title="Copy response"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: copiedIndex === i ? 'var(--green)' : 'var(--text-muted)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '3px',
                        fontSize: '.68rem',
                        padding: '1px 4px',
                      }}
                    >
                      {copiedIndex === i ? <Check size={12} /> : <Copy size={12} />}
                      {copiedIndex === i ? 'Copied' : 'Copy'}
                    </button>
                    <button
                      onClick={() => downloadSingleMessage(msg.content, i)}
                      title="Download this response as Markdown"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '3px',
                        fontSize: '.68rem',
                        padding: '1px 4px',
                      }}
                    >
                      <Download size={12} /> Download
                    </button>
                  </div>
                </div>
              )}
              {msg.role === 'error' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px', fontSize: '.72rem' }}>
                  <AlertCircle size={12} /> Error
                </div>
              )}

              {msg.role === 'assistant' || msg.role === 'system' ? (
                <div className="markdown-content">
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              ) : (
                <div style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</div>
              )}
            </div>
          ))}

          {loading && (
            <div className="chat-message assistant">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="spinner-sm" />
                <span style={{ color: 'var(--text-muted)', fontSize: '.82rem' }}>Analyzing threat intelligence report…</span>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {lookupResult && (
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', padding: '8px 16px', background: 'var(--bg-card)', borderTop: '1px solid var(--border)' }}>
            <span style={{ fontSize: '.72rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px', marginRight: '4px' }}>
              <Sparkles size={11} /> Quick prompts:
            </span>
            {SUGGESTIONS.map((s, idx) => (
              <button
                key={idx}
                onClick={() => sendQuery(s)}
                disabled={loading}
                style={{
                  fontSize: '.72rem',
                  padding: '3px 8px',
                  borderRadius: '12px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-secondary)',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  opacity: loading ? 0.6 : 1,
                  transition: 'all .15s',
                }}
              >
                {s}
              </button>
            ))}
          </div>
        )}

        <div className="chatbot-input-row">
          <input
            id="chat-input"
            type="text"
            placeholder={lookupResult ? `Ask about ${lookupResult.indicator}…` : 'Search an indicator on the dashboard first…'}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
          />
          <button
            onClick={handleSend}
            disabled={loading || !input.trim()}
            id="chat-send"
            aria-label="Send message"
          >
            <Send size={18} />
          </button>
        </div>
      </div>
    </div>
  )
}
