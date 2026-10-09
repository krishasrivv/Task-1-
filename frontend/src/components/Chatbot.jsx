import { useState, useRef, useEffect } from 'react'
import { Send, Bot, User, AlertCircle } from 'lucide-react'

export default function Chatbot({ lookupResult }) {
  const [messages, setMessages] = useState([
    {
      role: 'system',
      content: lookupResult
        ? 'I have the current threat intelligence report loaded. Ask me anything about the results.'
        : 'Search for an indicator first, then I can help you analyze the results.',
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Update system message when lookupResult changes
  useEffect(() => {
    if (lookupResult) {
      setMessages(prev => {
        const first = prev[0]
        if (first?.role === 'system' && first.content.includes('Search for an indicator')) {
          return [
            { role: 'system', content: 'Threat report loaded. Ask me anything about these results!' },
            ...prev.slice(1),
          ]
        }
        return prev
      })
    }
  }, [lookupResult])

  const handleSend = async () => {
    const text = input.trim()
    if (!text || loading) return

    const userMsg = { role: 'user', content: text }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const contextPayload = lookupResult || {}
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, context: contextPayload }),
      })
      const data = await res.json()

      if (data.error) {
        setMessages(prev => [...prev, { role: 'error', content: data.error }])
      } else {
        setMessages(prev => [...prev, { role: 'assistant', content: data.reply }])
      }
    } catch (err) {
      setMessages(prev => [
        ...prev,
        { role: 'error', content: 'Failed to reach the AI service. Is the backend running?' },
      ])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="chatbot-section">
      <div className="chatbot-panel">
        <div className="chatbot-header">
          <Bot size={20} style={{ color: 'var(--accent)' }} />
          <h3>ThreatIntel AI Assistant</h3>
          <span className="ai-badge">NVIDIA AI</span>
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
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px', fontSize: '.72rem', opacity: .7 }}>
                  <Bot size={12} /> ThreatIntel AI
                </div>
              )}
              {msg.role === 'error' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px', fontSize: '.72rem' }}>
                  <AlertCircle size={12} /> Error
                </div>
              )}
              <div style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</div>
            </div>
          ))}

          {loading && (
            <div className="chat-message assistant">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="spinner-sm" />
                <span style={{ color: 'var(--text-muted)', fontSize: '.82rem' }}>Analyzing…</span>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        <div className="chatbot-input-row">
          <input
            id="chat-input"
            type="text"
            placeholder={lookupResult ? 'Ask about this threat report…' : 'Search an indicator first…'}
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
