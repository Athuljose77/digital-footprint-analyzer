import { useState } from 'react'
import './App.css'

function App() {
  const [type, setType] = useState('username')
  const [value, setValue] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const analyze = async () => {
    if (!value.trim()) {
      setError(`Please enter a ${type}.`)
      return
    }

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch('http://127.0.0.1:8000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: type,
          value: value,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error('Something went wrong.')
      }

      setResult(data)
    } catch (err) {
      setError(
        'Could not connect to the analyzer. Make sure the backend is running.'
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app">
      <div className="container">

        <h1>Digital Footprint Analyzer</h1>

        <p className="subtitle">
          Check how exposed your digital identity is.
        </p>

        <div className="selector">
          <button
            className={type === 'username' ? 'active' : ''}
            onClick={() => {
              setType('username')
              setResult(null)
              setError('')
              setValue('')
            }}
          >
            Username
          </button>

          <button
            className={type === 'email' ? 'active' : ''}
            onClick={() => {
              setType('email')
              setResult(null)
              setError('')
              setValue('')
            }}
          >
            Email
          </button>
        </div>

        <label>
          Enter your {type}
        </label>

        <input
          type={type === 'email' ? 'email' : 'text'}
          placeholder={
            type === 'username'
              ? 'Enter username'
              : 'Enter email address'
          }
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />

        <button className="analyze-button" onClick={analyze}>
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>

        {error && <p className="error">{error}</p>}

        {result && type === 'username' && (
          <div className="result">

            <h2>Your Exposure Score</h2>

            <div className="score">
              {result.exposure_score} / 100
            </div>

            <p>
              Profiles found: {result.profiles_found}
            </p>

            <h3>Platform Results</h3>

            <div className="platforms">
              {result.results.map((item) => (
                <div className="platform" key={item.platform}>
                  <span>{item.platform}</span>

                  <span
                    className={
                      item.status === 'FOUND'
                        ? 'found'
                        : item.status === 'NOT_FOUND'
                        ? 'not-found'
                        : 'unknown'
                    }
                  >
                    {item.status}
                  </span>
                </div>
              ))}
            </div>

          </div>
        )}

        {result && type === 'email' && (
          <div className="result">

            <h2>Email Analysis</h2>

            <div className="email-status">
              {result.status}
            </div>

            <p>{result.message}</p>

            {result.domain && (
              <p>
                Domain: <strong>{result.domain}</strong>
              </p>
            )}

          </div>
        )}

      </div>
    </div>
  )
}

export default App