import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, ArrowLeft, ArrowRight, CheckCircle2, ChevronDown,
  CircleAlert, Clock, Network, Play, Radio, RefreshCw,
} from 'lucide-react'
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
const fmt = (v, digits = 0) =>
  v == null ? '—' : Number(v).toLocaleString(undefined, { maximumFractionDigits: digits })
const fmtBytes = (v) =>
  v == null ? '—' : v >= 1024 ? `${(v / 1024).toFixed(2)} KB` : `${fmt(v)} B`
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleTimeString() : '—')

function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge ${tone}`}>{children}</span>
}

function Stat({ icon: Icon, label, value, hint, flash }) {
  return (
    <div className={`traffic-stat${flash ? ' traffic-stat-flash' : ''}`}>
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
  const pct = max > 0 && value != null && value > 0 ? (value / max) * 100 : 0
  return (
    <div className="traffic-bar-row">
      <span className="traffic-bar-label">{label}</span>
      <div className="traffic-bar-track">
        <div className="traffic-bar-fill" style={{ width: `${pct}%` }} />
      </div>
      <strong>{text}</strong>
    </div>
  )
}

// Packet detail table
function PacketTable({ packets }) {
  if (!packets || packets.length === 0) return null
  return (
    <div className="pkt-table-wrap">
      <table className="pkt-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Direction</th>
            <th>Flags</th>
            <th>Payload (B)</th>
            <th>Frame (B)</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((p) => (
            <tr key={p.index} className={p.payload_bytes > 0 ? 'pkt-data' : ''}>
              <td className="pkt-idx">{p.index}</td>
              <td className={`pkt-dir ${p.direction === 'A -> B' ? 'atob' : 'btoa'}`}>
                {p.direction}
              </td>
              <td className="pkt-flags">{p.flags}</td>
              <td className={p.payload_bytes > 0 ? 'pkt-payload bold' : 'pkt-payload'}>
                {p.payload_bytes}
              </td>
              <td>{p.frame_bytes}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// Normalise one traffic doc into a flat display row
function toRow(t, exp) {
  const a = t.traffic_analysis || null
  const status = a?.analysis_status || null
  const done = status === 'completed'
  const s2rBytes = num(a?.sender_to_receiver_bytes)
  const r2sBytes = num(a?.receiver_to_sender_bytes)

  const senderName   = a?.sender_name   || t.sender_name   || exp?.sender_name   || null
  const senderId     = a?.sender_id     || t.device_a_id   || exp?.sender_id     || null
  const receiverName = a?.receiver_name || t.receiver_name || exp?.receiver_name || null
  const receiverId   = a?.receiver_id   || t.device_b_id   || exp?.receiver_id   || null
  const profileId    = a?.profile_id    || t.profile_id    || exp?.selected_profile_id || null
  const profileName  = a?.profile_name  || null
  const iface        = a?.capture_interface || t.capture_interface || null
  const capStatus    = a?.capture_status   || t.capture_status    || null

  return {
    raw: t,
    id: t.experiment_id,
    profile: profileId || '—',
    profileName,
    messageBytes:
      num(a?.message_size_bytes) ?? num(t.message_size_bytes) ?? num(exp?.message_size_bytes),
    state: done ? 'completed' : status === 'failed' ? 'failed' : 'pending',
    error: a?.analysis_error || null,
    packets: num(a?.total_packets),
    tcpPackets: num(a?.tcp_packets),
    appDataPackets: num(a?.application_data_packets),
    fileBytes: num(a?.total_captured_bytes),
    captureFileBytes: num(a?.capture_file_bytes) ?? num(t.capture_file_bytes),
    wireBytes:
      s2rBytes != null && r2sBytes != null ? s2rBytes + r2sBytes : null,
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
    pktList: a?.packets || [],
    senderName,
    senderId,
    receiverName,
    receiverId,
    iface,
    capStatus,
  }
}

const disp = (name, id) => name || id || '—'

// ---------------------------------------------------------------------------
// Main tab component
// ---------------------------------------------------------------------------
export default function TrafficTab() {
  const [traffic, setTraffic]       = useState([])
  const [experiments, setExperiments] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [showRaw, setShowRaw]       = useState(false)
  const [loading, setLoading]       = useState(true)
  const [running, setRunning]       = useState('')   // '' | 'all' | experimentId
  const [error, setError]           = useState('')
  const [lastRefresh, setLastRefresh] = useState(null)
  const [flashStats, setFlashStats]   = useState(false)
  const flashTimer = useRef(null)

  const triggerFlash = () => {
    setFlashStats(true)
    clearTimeout(flashTimer.current)
    flashTimer.current = setTimeout(() => setFlashStats(false), 1200)
  }

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [t, e] = await Promise.all([
        request('/api/traffic?limit=50'),
        request('/api/experiments?limit=100'),
      ])
      setTraffic(t)
      setExperiments(e)
      // Keep current selection if it still exists, otherwise default to first
      setSelectedId((cur) => {
        const ids = new Set(t.map((d) => d.experiment_id))
        return cur && ids.has(cur) ? cur : (t[0]?.experiment_id ?? null)
      })
      setLastRefresh(new Date())
      triggerFlash()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])

  const analyze = async (experimentId) => {
    setRunning(experimentId)
    setError('')
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
    setRunning('all')
    setError('')
    try {
      await request('/api/traffic/analyze-pending', { method: 'POST' })
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setRunning('')
    }
  }

  // ── Derived data ──────────────────────────────────────────────────────────
  const expById = useMemo(
    () => Object.fromEntries(experiments.map((e) => [e.experiment_id, e])),
    [experiments],
  )

  // rows ordered newest-first (API already returns _id desc)
  const rows = useMemo(
    () => traffic.map((t) => toRow(t, expById[t.experiment_id])),
    [traffic, expById],
  )

  const completed = useMemo(() => rows.filter((r) => r.state === 'completed'), [rows])
  const pending   = useMemo(() => rows.filter((r) => r.state === 'pending'), [rows])
  const failed    = useMemo(() => rows.filter((r) => r.state === 'failed'), [rows])

  const badgeText = useMemo(() => {
    const parts = [`${completed.length} analysed`]
    if (pending.length > 0) parts.push(`${pending.length} waiting`)
    if (failed.length > 0) parts.push(`${failed.length} failed`)
    return parts.join(' · ')
  }, [completed.length, pending.length, failed.length])

  const badgeTone = failed.length > 0 ? 'warning' : pending.length > 0 ? 'neutral' : 'good'

  const sum = (key) => completed.reduce((n, r) => n + (r[key] ?? 0), 0)
  const avg = (key) => {
    const vals = completed.map((r) => r[key]).filter((v) => v != null)
    return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null
  }

  // byProfile: C1 through C5 always present in canonical order
  const byProfile = useMemo(() => {
    const groups = {}
    ;['C1', 'C2', 'C3', 'C4', 'C5'].forEach((p) => {
      groups[p] = { n: 0, payload: 0, wire: 0, packets: 0 }
    })

    completed.forEach((r) => {
      if (!groups[r.profile]) {
        groups[r.profile] = { n: 0, payload: 0, wire: 0, packets: 0 }
      }
      const g = groups[r.profile]
      g.n += 1
      g.payload  += r.payload  ?? 0
      g.wire     += r.wireBytes ?? 0
      g.packets  += r.packets  ?? 0
    })

    return Object.entries(groups)
      .map(([profile, g]) => ({
        profile,
        n: g.n,
        payload: g.n > 0 ? g.payload / g.n : 0,
        wire:    g.n > 0 ? g.wire / g.n : 0,
        packets: g.n > 0 ? g.packets / g.n : 0,
      }))
      .sort((a, b) => a.profile.localeCompare(b.profile))
  }, [completed])

  const maxPayload = Math.max(1, ...byProfile.map((p) => p.payload))

  const selected = useMemo(() => rows.find((r) => r.id === selectedId), [rows, selectedId])

  const selectRow = (id) => {
    setSelectedId(id)
    setShowRaw(false)
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <section className="content-page">
      {/* Header */}
      <div className="traffic-header-row">
        <div className="page-title" style={{ marginBottom: 0 }}>
          <span className="eyebrow">Wire-level evidence</span>
          <h1>Traffic analysis</h1>
          <p>
            Packet dynamics and transport overhead from TShark captures, analysed with PyShark.
            Payloads are never decrypted here.
          </p>
        </div>
        <div className="traffic-toolbar-right">
          <div className="traffic-status-row">
            <Badge tone={badgeTone}>
              {badgeText}
            </Badge>
            {lastRefresh && (
              <span className="traffic-refresh-time">
                Updated {lastRefresh.toLocaleTimeString()}
              </span>
            )}
          </div>
          <div className="traffic-actions">
            {(pending.length > 0 || failed.length > 0) && (
              <button className="secondary" onClick={analyzePending} disabled={!!running}>
                {running === 'all'
                  ? <><RefreshCw className="spin" size={16} /> Analysing…</>
                  : <><Play size={16} /> Analyse pending</>}
              </button>
            )}
            <button className="secondary" onClick={load} disabled={loading || !!running}>
              <RefreshCw className={loading ? 'spin' : ''} size={16} />
              {loading ? ' Loading…' : ' Refresh'}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="error-box" style={{ marginTop: 16 }}>
          <CircleAlert size={17} /><span>{error}</span>
        </div>
      )}

      {!loading && !error && rows.length === 0 && (
        <div className="panel traffic-empty">
          <Radio size={22} />
          <div>
            <strong>No captures yet</strong>
            <p>
              Start <code>capture_monitor.py</code>, run an experiment and transmit, then click
              Refresh.
            </p>
          </div>
        </div>
      )}

      {rows.length > 0 && (
        <>
          {/* ── Summary stat cards ── */}
          <div className="traffic-stats" style={{ marginTop: 20 }}>
            <Stat flash={flashStats} icon={Activity} label="Captured sessions"
              value={fmt(rows.length)} hint={`${completed.length} analysed`} />
            <Stat flash={flashStats} icon={Network} label="Total packets"
              value={fmt(sum('packets'))}
              hint={completed.length ? `${fmt(avg('packets'), 1)} avg / session` : null} />
            <Stat flash={flashStats} icon={Radio} label="Avg TCP payload"
              value={fmtBytes(avg('payload'))} hint="handshake + data, per session" />
            <Stat flash={flashStats} icon={Clock} label="TCP retransmissions"
              value={fmt(sum('retrans'))}
              hint={completed.length && sum('retrans') === 0 ? 'clean loopback' : null} />
          </div>

          {/* ── Stacked: Session detail on top, Profile cost on bottom ── */}
          <div className="traffic-stack">

            {/* 1. Session detail (Top) */}
            <div className="panel session-detail-panel">
              <div className="panel-heading session-detail-heading">
                <div>
                  <h2>Session detail</h2>
                  <p>Inspect captured transmission dynamics, network overhead, and frame details.</p>
                </div>
                {/* Experiment selector dropdown */}
                <div className="traffic-exp-select-wrap">
                  <ChevronDown size={14} className="traffic-exp-select-icon" />
                  <select
                    className="traffic-exp-select"
                    value={selectedId ?? ''}
                    onChange={(e) => selectRow(e.target.value)}
                  >
                    {rows.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.id}  ·  {r.profile}
                        {r.state !== 'completed' ? `  [${r.state}]` : ''}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {selected && selected.state === 'completed' && (
                <>
                  {/* Experiment metadata */}
                  <div className="traffic-exp-meta">
                    <div>
                      <small>Sender (A)</small>
                      <strong>{disp(selected.senderName, selected.senderId)}</strong>
                    </div>
                    <div>
                      <small>Receiver (B)</small>
                      <strong>{disp(selected.receiverName, selected.receiverId)}</strong>
                    </div>
                    <div>
                      <small>Crypto profile</small>
                      <strong>
                        {selected.profile && selected.profileName && selected.profileName !== selected.profile
                          ? `${selected.profile} – ${selected.profileName}`
                          : selected.profileName || selected.profile || '—'}
                      </strong>
                    </div>
                    <div>
                      <small>Message size</small>
                      <strong>{fmtBytes(selected.messageBytes)}</strong>
                    </div>
                    <div>
                      <small>Capture interface</small>
                      <strong>{selected.iface || '—'}</strong>
                    </div>
                    <div>
                      <small>Capture status</small>
                      <strong>{selected.capStatus || '—'}</strong>
                    </div>
                  </div>

                  <div className="traffic-section-label">Traffic summary</div>
                  <div className="traffic-detail-grid">
                    <div><small>Total packets</small><strong>{fmt(selected.packets)}</strong></div>
                    <div><small>A → B packets</small><strong>{fmt(selected.s2r.packets)}</strong></div>
                    <div><small>B → A packets</small><strong>{fmt(selected.r2s.packets)}</strong></div>
                    <div><small>Data packets</small><strong>{fmt(selected.appDataPackets)}</strong></div>
                    <div><small>Captured bytes (sum of frames)</small><strong>{fmtBytes(selected.fileBytes)}</strong></div>
                    <div><small>TCP payload</small><strong>{fmtBytes(selected.payload)}</strong></div>
                    <div><small>Min / avg / max packet</small><strong>{fmt(selected.minSize)} / {fmt(selected.avgSize, 1)} / {fmt(selected.maxSize)} B</strong></div>
                    <div><small>Retransmissions</small><strong>{fmt(selected.retrans)}</strong></div>
                    <div><small>Traffic duration</small><strong>{selected.duration != null ? `${fmt(selected.duration, 3)} s` : '—'}</strong></div>
                    <div><small>Time window</small><strong>{fmtTime(selected.firstAt)} → {fmtTime(selected.lastAt)}</strong></div>
                    <div><small>Layers seen</small><strong>{selected.protocols.length ? selected.protocols.join(' · ') : '—'}</strong></div>
                  </div>

                  <div className="traffic-summary-split">
                    <div className="traffic-split-block">
                      <div className="traffic-section-label">Network overhead</div>
                      <div className="traffic-overhead-grid">
                        <div>
                          <small>Overhead vs plaintext</small>
                          <strong>
                            {fmtBytes(selected.overheadBytes)}
                            {selected.overheadPct != null ? ` (${fmt(selected.overheadPct, 1)}%)` : ''}
                          </strong>
                        </div>
                        {selected.captureFileBytes != null && (
                          <div>
                            <small>PCAPNG file on disk</small>
                            <strong>{fmtBytes(selected.captureFileBytes)}</strong>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="traffic-split-block">
                      <div className="traffic-section-label">Directional breakdown</div>
                      <div className="traffic-direction">
                        <div>
                          <ArrowRight size={15} /> Sender → Receiver
                          <strong>{fmt(selected.s2r.packets)} pkts · {fmtBytes(selected.s2r.bytes)}</strong>
                        </div>
                        <div>
                          <ArrowLeft size={15} /> Receiver → Sender
                          <strong>{fmt(selected.r2s.packets)} pkts · {fmtBytes(selected.r2s.bytes)}</strong>
                        </div>
                      </div>
                    </div>
                  </div>

                  {selected.pktList.length > 0 && (
                    <>
                      <div className="traffic-section-label">Packet details</div>
                      <PacketTable packets={selected.pktList} />
                    </>
                  )}

                  <button className="traffic-link" onClick={() => setShowRaw((v) => !v)}>
                    {showRaw ? 'Hide' : 'Show'} raw document
                  </button>
                  {showRaw && (
                    <pre className="traffic-raw">{JSON.stringify(selected.raw, null, 2)}</pre>
                  )}
                </>
              )}

              {selected && selected.state !== 'completed' && (
                <div className="traffic-pending">
                  <CircleAlert size={18} />
                  <div>
                    <strong>
                      {selected.state === 'failed' ? 'Analysis failed' : 'Captured — not yet analysed'}
                    </strong>
                    <p>
                      {selected.state === 'failed'
                        ? selected.error
                        : 'The .pcapng file is saved. Click below to run PyShark analysis now.'}
                    </p>
                    <button
                      className="secondary"
                      onClick={() => analyze(selected.id)}
                      disabled={!!running}
                    >
                      {running === selected.id
                        ? <><RefreshCw className="spin" size={16} /> Analysing…</>
                        : <><Play size={16} /> {selected.state === 'failed' ? 'Retry analysis' : 'Analyse now'}</>}
                    </button>
                  </div>
                </div>
              )}

              {!selected && (
                <p className="traffic-muted" style={{ marginTop: 12 }}>
                  No session selected.
                </p>
              )}
            </div>

            {/* 2. Traffic cost by profile (Bottom) */}
            <div className="panel profile-cost-panel">
              <div className="panel-heading compact">
                <div><div>
                  <h2>Traffic cost by profile</h2>
                  <p>
                    Average TCP payload per session across C1–C5. This is where key-exchange
                    size differs (RSA vs ECDH vs PSK).
                  </p>
                </div></div>
              </div>
              {byProfile.length === 0
                ? <p className="traffic-muted">No completed analyses yet.</p>
                : (
                  <div className="traffic-bars">
                    {byProfile.map((p) => (
                      <BarRow
                        key={p.profile}
                        label={p.profile}
                        value={p.payload}
                        max={maxPayload}
                        text={
                          p.n > 0
                            ? `${fmtBytes(p.payload)} payload · ${fmtBytes(p.wire)} on wire · ${fmt(p.packets, 1)} pkts · n=${p.n}`
                            : '0 B payload · 0 B on wire · 0 pkts · n=0'
                        }
                      />
                    ))}
                  </div>
                )}
            </div>

          </div>


        </>
      )}
    </section>
  )
}
