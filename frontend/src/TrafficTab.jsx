import { useCallback, useEffect, useMemo, useState } from 'react'
import { Activity, ArrowLeft, ArrowRight, CircleAlert, Clock, Network, Play, Radio, RefreshCw } from 'lucide-react'
import './traffic.css'

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------
const request = async (path, options = {}) => {
  const response = await fetch(path, options)
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
  return data
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const fmt = (v, digits = 0) => (v == null ? '—' : Number(v).toLocaleString(undefined, { maximumFractionDigits: digits }))
const fmtBytes = (v) => (v == null ? '—' : v >= 1024 ? `${(v / 1024).toFixed(2)} KB` : `${fmt(v)} B`)
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleTimeString() : '—')

function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge ${tone}`}>{children}</span>
}

function Stat({ icon: Icon, label, value, hint }) {
  return (
    <div className="traffic-stat">
      <div className="traffic-stat-icon"><Icon size={17} /></div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        {hint && <small>{hint}</small>}
      </div>
    </div>
  )
}

function BarRow({ label, value, max, text }) {
  const pct = max > 0 && value != null ? Math.max(2, (value / max) * 100) : 0
  return (
    <div className="traffic-bar-row">
      <span className="traffic-bar-label">{label}</span>
      <div className="traffic-bar-track"><div className="traffic-bar-fill" style={{ width: `${pct}%` }} /></div>
      <strong>{text}</strong>
    </div>
  )
}

// Normalise one document from GET /api/traffic. Field names match
// backend/analysis/traffic_analyzer.py (analyze_pcap return value).
function toRow(t, exp) {
  const a = t.traffic_analysis || null
  const status = a?.analysis_status || null // 'completed' | 'failed' | null (not analysed)
  const done = status === 'completed'
  const s2rBytes = num(a?.sender_to_receiver_bytes)
  const r2sBytes = num(a?.receiver_to_sender_bytes)
  return {
    raw: t,
    id: t.experiment_id,
    profile: t.profile_id || exp?.selected_profile_id || exp?.selected_profile || '—',
    messageBytes: num(a?.message_size_bytes) ?? num(t.message_size_bytes) ?? num(exp?.message_size_bytes),
    state: done ? 'completed' : status === 'failed' ? 'failed' : 'pending',
    error: a?.analysis_error || null,
    packets: num(a?.total_packets),
    tcpPackets: num(a?.tcp_packets),
    appDataPackets: num(a?.application_data_packets),
    fileBytes: num(a?.total_captured_bytes), // size of the .pcapng file, includes pcapng headers
    wireBytes: s2rBytes != null && r2sBytes != null ? s2rBytes + r2sBytes : null, // sum of packet lengths
    payload: num(a?.tcp_payload_bytes),
    minSize: num(a?.min_packet_size_bytes),
    avgSize: num(a?.average_packet_size_bytes),
    maxSize: num(a?.max_packet_size_bytes),
    retrans: num(a?.tcp_retransmissions),
    overheadBytes: num(a?.network_overhead_bytes),
    overheadPct: num(a?.network_overhead_percent),
    duration: num(a?.traffic_duration_seconds),
    firstAt: a?.first_packet_at,
    lastAt: a?.last_packet_at,
    protocols: a?.protocols_seen || [],
    s2r: { packets: num(a?.sender_to_receiver_packets), bytes: s2rBytes },
    r2s: { packets: num(a?.receiver_to_sender_packets), bytes: r2sBytes },
  }
}

// ---------------------------------------------------------------------------
// Tab
// ---------------------------------------------------------------------------
export default function TrafficTab() {
  const [traffic, setTraffic] = useState([])
  const [experiments, setExperiments] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [showRaw, setShowRaw] = useState(false)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState('') // experiment id, or 'all'
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [t, e] = await Promise.all([request('/api/traffic?limit=50'), request('/api/experiments?limit=100')])
      setTraffic(t); setExperiments(e)
      setSelectedId((cur) => cur ?? t[0]?.experiment_id ?? null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const analyze = async (experimentId) => {
    setRunning(experimentId); setError('')
    try {
      await request(`/api/traffic/${encodeURIComponent(experimentId)}/analyze`, { method: 'POST' })
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setRunning('')
    }
  }

  const analyzePending = async () => {
    setRunning('all'); setError('')
    try {
      await request('/api/traffic/analyze-pending', { method: 'POST' })
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setRunning('')
    }
  }

  const expById = useMemo(() => Object.fromEntries(experiments.map((e) => [e.experiment_id, e])), [experiments])
  const rows = useMemo(() => traffic.map((t) => toRow(t, expById[t.experiment_id])), [traffic, expById])
  const completed = rows.filter((r) => r.state === 'completed')
  const unfinished = rows.length - completed.length

  const sum = (key) => completed.reduce((n, r) => n + (r[key] ?? 0), 0)
  const avg = (key) => {
    const vals = completed.map((r) => r[key]).filter((v) => v != null)
    return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null
  }

  // Per-profile averages for the comparison chart
  const byProfile = useMemo(() => {
    const groups = {}
    completed.forEach((r) => {
      const g = (groups[r.profile] ||= { n: 0, payload: 0, wire: 0, packets: 0 })
      g.n += 1; g.payload += r.payload ?? 0; g.wire += r.wireBytes ?? 0; g.packets += r.packets ?? 0
    })
    return Object.entries(groups)
      .map(([profile, g]) => ({ profile, n: g.n, payload: g.payload / g.n, wire: g.wire / g.n, packets: g.packets / g.n }))
      .sort((a, b) => a.profile.localeCompare(b.profile))
  }, [completed])
  const maxPayload = Math.max(0, ...byProfile.map((p) => p.payload))

  const selected = rows.find((r) => r.id === selectedId)

  return (
    <section className="content-page">
      <div className="page-title">
        <span className="eyebrow">Wire-level evidence</span>
        <h1>Traffic analysis</h1>
        <p>Packet dynamics and transport overhead from TShark captures, analysed with PyShark. Payloads are never decrypted here.</p>
      </div>

      <div className="traffic-toolbar">
        <Badge tone={completed.length ? 'good' : 'warning'}>{completed.length} analysed · {unfinished} waiting</Badge>
        <div className="traffic-actions">
          {unfinished > 0 && (
            <button className="secondary" onClick={analyzePending} disabled={!!running}>
              {running === 'all' ? <><RefreshCw className="spin" size={16} /> Analysing…</> : <><Play size={16} /> Analyse pending</>}
            </button>
          )}
          <button className="secondary" onClick={load} disabled={loading || !!running}>
            <RefreshCw className={loading ? 'spin' : ''} size={16} /> Refresh
          </button>
        </div>
      </div>

      {error && <div className="error-box"><CircleAlert size={17} /><span>{error}</span></div>}

      {!loading && !error && rows.length === 0 && (
        <div className="panel traffic-empty">
          <Radio size={22} />
          <div>
            <strong>No captures yet</strong>
            <p>Start <code>capture_monitor.py</code>, run an experiment and transmit, then click Refresh.</p>
          </div>
        </div>
      )}

      {rows.length > 0 && (
        <>
          <div className="traffic-stats">
            <Stat icon={Activity} label="Captured sessions" value={fmt(rows.length)} hint={`${completed.length} analysed`} />
            <Stat icon={Network} label="Total packets" value={fmt(sum('packets'))} hint={completed.length ? `${fmt(avg('packets'), 1)} avg / session` : null} />
            <Stat icon={Radio} label="Avg TCP payload" value={fmtBytes(avg('payload'))} hint="handshake + data, per session" />
            <Stat icon={Clock} label="TCP retransmissions" value={fmt(sum('retrans'))} hint={completed.length && sum('retrans') === 0 ? 'clean loopback' : null} />
          </div>

          <div className="traffic-grid">
            <div className="panel">
              <div className="panel-heading compact"><div><div><h2>Traffic cost by profile</h2><p>Average TCP payload per session. This is where key-exchange size differs, such as RSA versus ECDH versus PSK.</p></div></div></div>
              {byProfile.length === 0 ? <p className="traffic-muted">No completed analyses yet.</p> : (
                <div className="traffic-bars">
                  {byProfile.map((p) => (
                    <BarRow key={p.profile} label={p.profile} value={p.payload} max={maxPayload}
                      text={`${fmtBytes(p.payload)} payload · ${fmtBytes(p.wire)} on wire · ${fmt(p.packets, 1)} pkts · n=${p.n}`} />
                  ))}
                </div>
              )}
            </div>

            <div className="panel">
              <div className="panel-heading compact"><div><div><h2>Session detail</h2><p className="mono">{selected ? selected.id : 'Select a capture'}</p></div></div></div>
              {selected && selected.state === 'completed' && (
                <>
                  <div className="traffic-detail-grid">
                    <div><small>Profile</small><strong>{selected.profile}</strong></div>
                    <div><small>Plaintext</small><strong>{fmtBytes(selected.messageBytes)}</strong></div>
                    <div><small>Packets (TCP / data-bearing)</small><strong>{fmt(selected.packets)} ({fmt(selected.tcpPackets)} / {fmt(selected.appDataPackets)})</strong></div>
                    <div><small>TCP payload</small><strong>{fmtBytes(selected.payload)}</strong></div>
                    <div><small>On wire (sum of packet lengths)</small><strong>{fmtBytes(selected.wireBytes)}</strong></div>
                    <div><small>Capture file size</small><strong>{fmtBytes(selected.fileBytes)}</strong></div>
                    <div><small>Packet size min / avg / max</small><strong>{fmt(selected.minSize)} / {fmt(selected.avgSize, 1)} / {fmt(selected.maxSize)} B</strong></div>
                    <div><small>Overhead vs plaintext</small><strong>{fmtBytes(selected.overheadBytes)}{selected.overheadPct != null ? ` (${fmt(selected.overheadPct, 1)}%)` : ''}</strong></div>
                    <div><small>Duration</small><strong>{selected.duration != null ? `${fmt(selected.duration, 3)} s` : '—'}</strong></div>
                    <div><small>Retransmissions</small><strong>{fmt(selected.retrans)}</strong></div>
                    <div><small>Time window</small><strong>{fmtTime(selected.firstAt)} → {fmtTime(selected.lastAt)}</strong></div>
                    <div><small>Layers seen</small><strong>{selected.protocols.length ? selected.protocols.join(' · ') : '—'}</strong></div>
                  </div>
                  <div className="traffic-direction">
                    <div><ArrowRight size={15} /> Sender → Receiver<strong>{fmt(selected.s2r.packets)} pkts · {fmtBytes(selected.s2r.bytes)}</strong></div>
                    <div><ArrowLeft size={15} /> Receiver → Sender<strong>{fmt(selected.r2s.packets)} pkts · {fmtBytes(selected.r2s.bytes)}</strong></div>
                  </div>
                  <button className="traffic-link" onClick={() => setShowRaw((v) => !v)}>{showRaw ? 'Hide' : 'Show'} raw document</button>
                  {showRaw && <pre className="traffic-raw">{JSON.stringify(selected.raw, null, 2)}</pre>}
                </>
              )}
              {selected && selected.state !== 'completed' && (
                <div className="traffic-pending">
                  <CircleAlert size={18} />
                  <div>
                    <strong>{selected.state === 'failed' ? 'Analysis failed' : 'Captured, not analysed yet'}</strong>
                    <p>{selected.state === 'failed' ? selected.error : 'The capture is saved, but its packet metrics have not been computed.'}</p>
                    <button className="secondary" onClick={() => analyze(selected.id)} disabled={!!running}>
                      {running === selected.id ? <><RefreshCw className="spin" size={16} /> Analysing…</> : <><Play size={16} /> {selected.state === 'failed' ? 'Retry analysis' : 'Analyse now'}</>}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="panel table-panel">
            <div className="panel-heading compact"><div><div><h2>Captured sessions</h2><p>Click a row for details.</p></div></div></div>
            <div className="traffic-table">
              <div className="traffic-row traffic-head">
                <span>Experiment</span><span>Profile</span><span>Plaintext</span><span>Packets</span><span>TCP payload</span><span>Overhead</span><span>Status</span>
              </div>
              {rows.map((r) => (
                <button key={r.id} className={`traffic-row ${r.id === selectedId ? 'active' : ''}`} onClick={() => setSelectedId(r.id)}>
                  <span className="mono">{r.id}</span>
                  <span>{r.profile}</span>
                  <span>{fmtBytes(r.messageBytes)}</span>
                  <span>{fmt(r.packets)}</span>
                  <span>{fmtBytes(r.payload)}</span>
                  <span>{r.overheadPct != null ? `${fmt(r.overheadPct, 1)}%` : '—'}</span>
                  <span><Badge tone={r.state === 'completed' ? 'good' : r.state === 'failed' ? 'bad' : 'warning'}>{r.state === 'completed' ? 'analysed' : r.state}</Badge></span>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </section>
  )
}
