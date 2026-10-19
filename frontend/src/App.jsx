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
      const response = await fetch(
        'http://127.0.0.1:8000/analyze',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            type: type,
            value: value.trim(),
          }),
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          data.message || 'Something went wrong.'
        )
      }

      setResult(data)
    } catch (err) {
      setError(
        err.message ||
          'Could not connect to the analyzer. Make sure the backend is running.'
      )
    } finally {
      setLoading(false)
    }
  }

  const changeType = (newType) => {
    setType(newType)
    setValue('')
    setResult(null)
    setError('')
  }

  return (
    <div className="app">
      <div className="container">

        <h1>Digital Footprint Analyzer</h1>

        <p className="subtitle">
          Check how exposed your digital identity is.
        </p>

        {/* TYPE SELECTOR */}

        <div className="selector">

          <button
            className={
              type === 'username'
                ? 'active'
                : ''
            }
            onClick={() =>
              changeType('username')
            }
          >
            Username
          </button>

          <button
            className={
              type === 'email'
                ? 'active'
                : ''
            }
            onClick={() =>
              changeType('email')
            }
          >
            Email
          </button>

        </div>

        {/* INPUT */}

        <label>
          Enter your {type}
        </label>

        <input
          type={
            type === 'email'
              ? 'email'
              : 'text'
          }
          placeholder={
            type === 'username'
              ? 'Enter username'
              : 'Enter email address'
          }
          value={value}
          onChange={(e) =>
            setValue(e.target.value)
          }
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              analyze()
            }
          }}
        />

        {/* ANALYZE BUTTON */}

        <button
          className="analyze-button"
          onClick={analyze}
          disabled={loading}
        >
          {loading
            ? 'Analyzing...'
            : 'Analyze'}
        </button>

        {/* ERROR */}

        {error && (
          <p className="error">
            {error}
          </p>
        )}

        {/* ================================= */}
        {/* USERNAME RESULTS */}
        {/* ================================= */}

        {result &&
          type === 'username' && (
            <div className="result">

              <h2>
                Your Exposure Score
              </h2>

              <div className="score">
                {result.exposure_score ?? 0}
                {' / 100'}
              </div>

              {result.score_basis && (
                <p className="notice">
                  {result.score_basis}
                </p>
              )}

              {result.message && (
                <p className="summary">
                  {result.message}
                </p>
              )}

              <p>
                Profiles found:{' '}
                <strong>
                  {result.profiles_found ?? 0}
                </strong>
              </p>

              <p>
                Confirmed by the platform page:{' '}
                <strong>
                  {result.confirmed_count ?? 0}
                </strong>
              </p>

              <p>
                Platforms checked:{' '}
                <strong>
                  {result.platform_count ?? 0}
                </strong>
              </p>

              {result.unknown_count > 0 && (
                <p>
                  Unable to verify:{' '}
                  <strong>
                    {result.unknown_count}
                  </strong>
                </p>
              )}

              <h3>
                Platform Results
              </h3>

              <div className="platforms">

                {result.results && result.results.length === 0 && (
                  <p>
                    No candidate profiles were reported.
                  </p>
                )}

                {result.results &&
                  result.results.map((item, index) => {
                    const verification =
                      item.verification || 'inconclusive'
                    const confirmed =
                      verification === 'confirmed'
                    const missing =
                      verification === 'not_found'
                    return (
                      <div
                        className="platform"
                        key={`${item.platform}-${item.profile_url}-${index}`}
                      >

                        <div className="platform-main">
                          <span>
                            {item.platform}
                          </span>

                          {item.verification_note && (
                            <span className="platform-note">
                              {item.verification_note}
                            </span>
                          )}

                          {item.checked_at && (
                            <span className="platform-note">
                              Checked {item.checked_at}
                              {item.http_status
                                ? ` · HTTP ${item.http_status}`
                                : ' · no response'}
                            </span>
                          )}
                        </div>

                        <div className="platform-side">
                          <span
                            className={
                              confirmed
                                ? 'found'
                                : missing
                                ? 'not-found'
                                : 'unknown'
                            }
                          >
                            {confirmed
                              ? 'CONFIRMED'
                              : missing
                              ? 'NOT FOUND'
                              : 'UNVERIFIED'}
                          </span>

                          {item.profile_url && (
                            <a
                              href={item.profile_url}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              View profile
                            </a>
                          )}
                        </div>

                      </div>
                    )
                  })}

              </div>

              <p className="privacy-note">
                A username lookup asks public platforms directly and reads each
                candidate page once to check whether it really shows this
                handle. A page that exists is evidence of an account, not proof
                of who owns it.
              </p>

            </div>
          )}

        {/* ================================= */}
        {/* EMAIL RESULTS */}
        {/* ================================= */}

        {result &&
          type === 'email' && (
            <div className="result">

              <h2>
                Email Analysis
              </h2>

              <p>
                Email:{' '}
                <strong>
                  {result.input || value}
                </strong>
              </p>

              {/* INVALID EMAIL */}

              {result.status === 'ERROR' && (
                <p className="error">
                  {result.message}
                </p>
              )}

              {/* EMAIL CHECK UNAVAILABLE */}

              {result.status === 'UNAVAILABLE' && (
                <div className="email-unavailable">

                  <h3>
                    Breach Check Status
                  </h3>

                  <p>
                    {result.message}
                  </p>

                  <p>
                    <strong>
                      Status:
                    </strong>{' '}
                    Not checked
                  </p>

                </div>
              )}

              {/* SUCCESSFUL EMAIL CHECK */}

              {result.status !== 'ERROR' &&
                result.status !== 'UNAVAILABLE' && (
                  <>

                    <h3>
                      Exposure Score
                    </h3>

                    <div className="score">
                      {result.exposure_score ?? 0}
                      {' / 100'}
                    </div>

                    <h3>
                      Known Breaches:{' '}
                      {result.breach_count ?? 0}
                    </h3>

                    {/* NO BREACHES */}

                    {result.breach_count === 0 && (
                      <p>
                        No known breaches found.
                      </p>
                    )}

                    {/* BREACH DETAILS */}

                    {result.breach_count > 0 && (
                      <div className="breaches">

                        {result.breaches &&
                          result.breaches.map(
                            (breach, index) => (
                              <div
                                className="breach"
                                key={index}
                              >

                                <h3>
                                  {breach.name ||
                                    'Unknown breach'}
                                </h3>

                                <p>
                                  <strong>
                                    Records Exposed:
                                  </strong>{' '}
                                  {breach.records_exposed ??
                                    'Unknown'}
                                </p>

                                <p>
                                  <strong>
                                    Breach Date:
                                  </strong>{' '}
                                  {breach.breach_date ??
                                    'Unknown'}
                                </p>

                                <p>
                                  <strong>
                                    Industry:
                                  </strong>{' '}
                                  {breach.industry ??
                                    'Unknown'}
                                </p>

                                <p>
                                  <strong>
                                    Password Risk:
                                  </strong>{' '}
                                  {breach.password_risk ??
                                    'Unknown'}
                                </p>

                                <p>
                                  <strong>
                                    Verified:
                                  </strong>{' '}
                                  {breach.verified
                                    ? 'Yes'
                                    : 'No'}
                                </p>

                                <p>
                                  <strong>
                                    Exposed Data:
                                  </strong>{' '}

                                  {breach.exposed_data &&
                                  breach.exposed_data.length > 0
                                    ? breach.exposed_data.join(', ')
                                    : 'Not specified'}

                                </p>

                              </div>
                            )
                          )}

                      </div>
                    )}

                    {/* EXPOSED SITES */}

                    {result.exposed_sites && (
                      <div className="email-presence">

                        <h3>
                          Sites Where Email Was
                          Exposed in Known Breaches
                        </h3>

                        {result.exposed_sites.length === 0 ? (
                          <p>
                            No known exposed sites found.
                          </p>
                        ) : (
                          <div className="platforms">

                            {result.exposed_sites.map(
                              (site, index) => (
                                <div
                                  className="platform"
                                  key={`${site.site}-${index}`}
                                >

                                  <span>
                                    {site.site}
                                  </span>

                                  <span className="found">
                                    EXPOSED
                                  </span>

                                </div>
                              )
                            )}

                          </div>
                        )}

                      </div>
                    )}

                  </>
                )}

            </div>
          )}

      </div>
    </div>
  )
}

export default App
