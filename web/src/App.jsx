import { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, Link, useParams } from 'react-router-dom'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000'
const smallErr = (e) => String(e?.message || e || '')

async function fetchJSON(path, token) {
  const headers = { Accept: 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(`${API_BASE}${path}`, { headers })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

function Layout({ token, setToken, children }) {
  useEffect(() => { localStorage.setItem('token', token || '') }, [token])

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', padding: 16, textAlign: 'left' }}>
      <h1>Unebrasil</h1>

      <nav style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
        <Link to="/">Feed</Link>
        <Link to="/my-votes">Minhas votações</Link>
      </nav>
      <div style={{ fontSize: 12, opacity: 0.7, marginBottom: 12 }}>
        API: <code>{API_BASE}</code>
      </div>

      <div style={{ marginBottom: 12 }}>
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="Cole seu TOKEN aqui (sem 'Bearer ')"
          style={{ width: '100%', padding: 8 }}
        />
      </div>

      {children}
    </div>
  )
}

function Feed({ token }) {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [items, setItems] = useState([])

  useEffect(() => {
    let ok = true
    ;(async () => {
      try {
        setLoading(true); setError('')
        const data = await fetchJSON('/decisions?archived=false&sort=priority&page=1&page_size=20', token)
        if (ok) setItems(data.items || [])
      } catch (e) {
        if (ok) setError(smallErr(e))
      } finally {
        if (ok) setLoading(false)
      }
    })()
    return () => { ok = false }
  }, [token])
  return (
    <div>
      <h2>Feed</h2>
      {loading && <p>Carregando…</p>}
      {error && <p style={{ color: '#b00' }}>Erro: {error}</p>}

      {!loading && !error && (
        <ol style={{ paddingLeft: 18 }}>
          {items.map((d) => (
            <li key={d.id} style={{ marginBottom: 10 }}>
              <div style={{ fontWeight: 600 }}>
                <Link to={`/d/${d.id}`}>{d.title}</Link>
              </div>
              <div style={{ fontSize: 12, opacity: 0.8 }}>
                id {d.id} · {d.source} · {String(d.occurred_at || d.created_at)} · oficiais: {String(d.has_official_votes)}
              </div>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

function MyVotes({ token }) {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [items, setItems] = useState([])

  useEffect(() => {
    let ok = true
    ;(async () => {
      try {
        setLoading(true); setError('')
        if (!token) { if (ok) setItems([]); return }
        const data = await fetchJSON('/me/votes?page=1&page_size=50', token)
        if (ok) setItems(data.items || [])
      } catch (e) {
        if (ok) setError(smallErr(e))
      } finally {
        if (ok) setLoading(false)
      }
    })()
    return () => { ok = false }
  }, [token])
  return (
    <div>
      <h2>Minhas votações</h2>
      {!token && <p>Cole seu token ali em cima pra ver suas votações.</p>}
      {loading && token && <p>Carregando…</p>}
      {error && <p style={{ color: '#b00' }}>Erro: {error}</p>}

      {!loading && !error && token && (
        <ol style={{ paddingLeft: 18 }}>
          {items.map((it, idx) => {
            const t = Number(it?.citizen?.total || 0)
            const c = Number(it?.citizen?.concordo || 0)
            const d = Number(it?.citizen?.discordo || 0)
            const pc = t ? ((c * 100) / t).toFixed(1) : '0.0'
            const pd = t ? ((d * 100) / t).toFixed(1) : '0.0'
            return (
              <li key={`${it?.decision?.id || idx}`} style={{ marginBottom: 10 }}>
                <div style={{ fontWeight: 600 }}>
                  <Link to={`/d/${it.decision.id}`}>{it.decision.title}</Link>
                </div>
                <div style={{ fontSize: 12, opacity: 0.85 }}>
                  meu voto: <b>{it.my_choice}</b> · público: {pc}% concordo / {pd}% discordo (total {t})
                </div>
              </li>
            )
          })}
        </ol>
      )}
    </div>
  )
}

function DecisionPage({ token }) {
  const { id } = useParams()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [data, setData] = useState(null)

  useEffect(() => {
    let ok = true
    ;(async () => {
      try {
        setLoading(true); setError('')
        const d = await fetchJSON(`/decisions/${id}`, token)
        if (ok) setData(d)
      } catch (e) {
        if (ok) setError(smallErr(e))
      } finally {
        if (ok) setLoading(false)
      }
    })()
    return () => { ok = false }
  }, [id, token])
  return (
    <div>
      <h2>Decisão #{id}</h2>
      {loading && <p>Carregando…</p>}
      {error && <p style={{ color: '#b00' }}>Erro: {error}</p>}

      {!loading && !error && data && (
        <div style={{ padding: 12, border: '1px solid #ddd', borderRadius: 8 }}>
          <div style={{ fontWeight: 700, marginBottom: 8 }}>{data.title}</div>
          <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 8 }}>
            {data.source} · {String(data.occurred_at || data.created_at)} · oficiais: {String(data.has_official_votes)}
          </div>
          {data.citizen && (
            <div style={{ fontSize: 13 }}>
              <b>Público</b>: total {data.citizen.total} · concordo {data.citizen.concordo} · discordo {data.citizen.discordo}
            </div>
          )}
          {data.my_vote && (
            <div style={{ fontSize: 13, marginTop: 8 }}>
              <b>Meu voto</b>: {String(data.my_vote.choice || '-')}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function AppRoutes({ token }) {
  return (
    <Routes>
      <Route path="/" element={<Feed token={token} />} />
      <Route path="/my-votes" element={<MyVotes token={token} />} />
      <Route path="/d/:id" element={<DecisionPage token={token} />} />
    </Routes>
  )
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '')
  return (
    <BrowserRouter>
      <Layout token={token} setToken={setToken}>
        <AppRoutes token={token} />
      </Layout>
    </BrowserRouter>
  )
}
