import { useState } from 'react'
import './App.css'

function App() {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)

  const handleScan = async (e) => {
    e.preventDefault()
    if (!target) return

    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const response = await fetch('http://127.0.0.1:8000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target })
      })

      if (!response.ok) {
        throw new Error('Scan failed. Ensure target is valid and backend is running.')
      }

      const data = await response.json()
      setResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const getScoreColor = (score) => {
    if (score > 70) return '#ff4757'
    if (score > 40) return '#ffa502'
    if (score > 20) return '#eccc68'
    return '#2ed573'
  }

  return (
    <div className="container">
      <header className="header">
        <h1>CyberPulse <span className="highlight">SaaS</span></h1>
        <p>Enterprise Attack Surface Analyzer</p>
      </header>

      <div className="glass-panel search-section">
        <form onSubmit={handleScan}>
          <input 
            type="text" 
            placeholder="Enter domain (e.g., example.com)" 
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="search-input"
          />
          <button type="submit" className="scan-btn" disabled={loading}>
            {loading ? 'Scanning...' : 'Initiate Recon'}
          </button>
        </form>
        {error && <p className="error-text">{error}</p>}
      </div>

      {loading && (
        <div className="scanning-animation">
          <div className="radar"></div>
          <p>Analyzing external attack surface...</p>
        </div>
      )}

      {results && (
        <div className="results-grid">
          
          <div className="glass-panel score-card" style={{ borderTop: `4px solid ${getScoreColor(results.threat_score)}` }}>
            <h3>Threat Score</h3>
            <div className="score-number" style={{ color: getScoreColor(results.threat_score) }}>
              {results.threat_score}<span>/100</span>
            </div>
            <p className="risk-level">Risk Level: <strong>{results.risk_level}</strong></p>
            <p className="ip-info">Resolved IP: {results.ip_address}</p>
          </div>

          <div className="glass-panel details-card">
            <h3>Exposed Infrastructure (Ports)</h3>
            {results.open_ports.length > 0 ? (
              <ul className="port-list">
                {results.open_ports.map((p, idx) => (
                  <li key={idx} className={p.port === 80 || p.port === 443 ? 'safe-port' : 'danger-port'}>
                    Port {p.port} - {p.service}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="success-text">No dangerous ports exposed.</p>
            )}
          </div>

          <div className="glass-panel details-card">
            <h3>Security Header Posture</h3>
            <div className="header-grid">
              <div>
                <h4>Present</h4>
                <ul className="present-list">
                  {results.security_headers.present?.map((h, i) => <li key={i}>✅ {h}</li>)}
                </ul>
              </div>
              <div>
                <h4>Missing</h4>
                <ul className="missing-list">
                  {results.security_headers.missing?.map((h, i) => <li key={i}>❌ {h}</li>)}
                </ul>
              </div>
            </div>
          </div>

        </div>
      )}
    </div>
  )
}

export default App
