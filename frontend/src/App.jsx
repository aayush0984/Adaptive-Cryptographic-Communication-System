import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  ArrowRight,
  Battery,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Cpu,
  Database,
  Gauge,
  HardDrive,
  History,
  KeyRound,
  LockKeyhole,
  Network,
  Radio,
  RefreshCw,
  Send,
  Server,
  ShieldCheck,
  Sparkles,
  XCircle,
  Zap,
} from 'lucide-react'
import TrafficTab from './TrafficTab'
import TransmissionTimeline from './TransmissionTimeline'

const api = async (path, options = {}) => {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
  return data
}

const fmtRam = (kb) => {
  if (kb >= 1024 * 1024) return `${(kb / 1024 / 1024).toFixed(kb >= 4 * 1024 * 1024 ? 0 : 1)} GB`
  if (kb >= 1024) return `${(kb / 1024).toFixed(0)} MB`
  return `${Number(kb).toFixed(0)} KB`
}

const profileFamily = (profile) => {
  const family = profile?.key_establishment?.family || '—'
  const param = profile?.key_establishment?.parameter || ''
  return `${family}${param ? ` ${param}` : ''}`
}

function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge ${tone}`}>{children}</span>
}

function Metric({ icon: Icon, label, value }) {
  return (
    <div className="metric">
      <div className="metric-icon"><Icon size={16} /></div>
      <div><span>{label}</span><strong>{value}</strong></div>
    </div>
  )
}

function DevicePreview({ label, device }) {
  if (!device) return null
  return (
    <div className="device-preview">
      <div className="device-title-row">
        <div>
          <span className="eyebrow">{label}</span>
          <h3>{device.name}</h3>
        </div>
        <Badge tone={device.power_source === 'battery' ? 'warning' : 'neutral'}>
          {device.power_source}
        </Badge>
      </div>
      <div className="device-metrics">
        <Metric icon={Cpu} label="CPU" value={device.cpu_level} />
        <Metric icon={HardDrive} label="RAM" value={fmtRam(device.available_memory_kb)} />
        <Metric icon={Gauge} label="Latency cap" value={`${device.latency_requirement_ms} ms`} />
        <Metric icon={ShieldCheck} label="Security" value={device.security_requirement} />
      </div>
    </div>
  )
}

function WeightBars({ weights = {}, pressures = {} }) {
  const rows = [
    ['Time', 'wt', 'p_time', Activity],
    ['Memory', 'wm', 'p_memory', HardDrive],
    ['Communication', 'wc', 'p_communication', Network],
    ['Energy', 'we', 'p_energy', Zap],
  ]
  return (
    <div className="weight-stack">
      {rows.map(([name, wk, pk, Icon]) => {
        const pct = Math.round((weights[wk] || 0) * 1000) / 10
        return (
          <div className="weight-row" key={name}>
            <div className="weight-label"><Icon size={15} /><span>{name}</span></div>
            <div className="weight-track"><div className="weight-fill" style={{ width: `${pct}%` }} /></div>
            <strong>{pct}%</strong>
            <small>p={Number(pressures[pk] || 0).toFixed(2)}</small>
          </div>
        )
      })}
    </div>
  )
}

function CandidateCard({ item, selectedId }) {
  const feasible = item.compatible
  const selected = item.profile_id === selectedId
  const latency = item.predicted_sender_total_ms != null && item.predicted_receiver_total_ms != null
    ? item.predicted_sender_total_ms + item.predicted_receiver_total_ms
    : null
  return (
    <div className={`candidate ${selected ? 'selected' : ''}`}>
      <div className="candidate-main">
        <div className={`status-dot ${feasible ? 'good' : 'bad'}`} />
        <div>
          <div className="candidate-name">
            <strong>{item.profile_id}</strong>
            <span>{item.profile_name}</span>
            {selected && <Badge tone="good">selected</Badge>}
          </div>
          <div className="candidate-meta">
            <span>{item.security_level} security</span>
            {latency != null && <span>{latency.toFixed(2)} ms predicted</span>}
            {item.predicted_sender_peak_kb != null && <span>{item.predicted_sender_peak_kb.toFixed(2)} KB peak</span>}
            {item.predicted_application_bytes != null && <span>{item.predicted_application_bytes} B app data</span>}
          </div>
        </div>
      </div>
      <div className="candidate-score">
        {item.final_score != null ? <><small>score</small><strong>{item.final_score.toFixed(4)}</strong></> : <Badge tone={feasible ? 'neutral' : 'bad'}>{feasible ? 'feasible' : 'rejected'}</Badge>}
      </div>
      {!feasible && item.rejection_reasons?.length > 0 && (
        <div className="reasons">{item.rejection_reasons[0]}{item.rejection_reasons.length > 1 ? ` +${item.rejection_reasons.length - 1} more` : ''}</div>
      )}
    </div>
  )
}

// The current API supplies selection failures as a Python-formatted string.
// Parse only its profile/reason text for display; never execute or evaluate it.
function parseSelectionFailure(message) {
  const text = String(message || '')
  if (!text.includes('no_profile_satisfies_constraints')) return null
  const rows = []
  const rowPattern = /'(C\d+)': \[((?:[^\]]|\](?![,}]))*)\]/g
  let match
  while ((match = rowPattern.exec(text)) !== null) {
    const reasons = [...match[2].matchAll(/"((?:\\.|[^"\\])*)"/g)]
      .map((m) => m[1].replace(/\\"/g, '"'))
    rows.push({ id: match[1], reasons })
  }
  if (!rows.length) return { status: 'incompatible', rows: [] }
  const isEvidence = (reason) => /insufficient benchmark evidence|no benchmark data/i.test(reason)
  const hasEligibleProfile = rows.some((row) => row.reasons.length && row.reasons.every(isEvidence))
  return { status: hasEligibleProfile ? 'missing-evidence' : 'incompatible', rows }
}

function readableReason(reason) {
  if (/insufficient benchmark evidence|no benchmark data/i.test(reason)) return 'Missing benchmark measurements'
  if (/security_requirement/i.test(reason)) return 'Security requirement not met'
  if (/cpu_level|minimum_cpu_level/i.test(reason)) return 'Insufficient CPU capability'
  if (/memory|ram/i.test(reason)) return 'Insufficient available memory'
  if (/latency/i.test(reason)) return 'Latency requirement exceeded'
  if (/packet|payload|communication/i.test(reason)) return 'Communication constraint not met'
  return reason.length > 110 ? reason.slice(0, 107) + '…' : reason
}

function SelectionFailure({ message, sender, receiver }) {
  const failure = parseSelectionFailure(message)
  if (!failure) return <div className="error-box"><CircleAlert size={17} /><span>{message}</span></div>
  const missing = failure.status === 'missing-evidence'
  return (
    <section className="selection-failure" role="status">
      <div className="selection-failure-heading">
        <CircleAlert size={21} />
        <div>
          <h3>{missing ? 'Benchmark evidence needed' : 'No compatible cryptographic profile'}</h3>
          <p>{sender?.name || 'Sender'} → {receiver?.name || 'Receiver'}</p>
        </div>
        <Badge tone={missing ? 'warning' : 'bad'}>{missing ? 'Incomplete evidence' : 'Incompatible'}</Badge>
      </div>
      <p className="selection-failure-summary">
        {missing
          ? 'At least one profile passes the available device checks, but its performance records are missing.'
          : 'None of the evaluated profiles meets both devices’ hardware and security constraints.'}
      </p>
      {failure.rows.length > 0 && (
        <div className="failure-profile-list">
          {failure.rows.map((row) => (
            <div className="failure-profile" key={row.id}>
              <strong>{row.id}</strong>
              <div>{[...new Set(row.reasons.map(readableReason))].map((reason, i) => <span key={i}>{reason}</span>)}</div>
            </div>
          ))}
        </div>
      )}
      <p className="failure-advice">
        {missing
          ? 'Run benchmarks for the missing device/profile combinations and retry. Local laptop benchmarks are not physical IoT-device measurements.'
          : 'Choose a pairing with compatible security and CPU requirements. Rejection is a valid selection outcome.'}
      </p>
    </section>
  )
}

function ExperimentTab({ devices, health }) {
  const [senderId, setSenderId] = useState('')
  const [receiverId, setReceiverId] = useState('')
  const [message, setMessage] = useState('temperature=27.4; humidity=63')
  const [selection, setSelection] = useState(null)
  const [transmission, setTransmission] = useState(null)
  const [stages, setStages] = useState(null)
  const [busy, setBusy] = useState(false)
  const [sending, setSending] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (devices.length && !senderId) setSenderId(devices[0].device_id)
    if (devices.length > 1 && !receiverId) setReceiverId(devices[1].device_id)
  }, [devices, senderId, receiverId])

  const sender = devices.find((d) => d.device_id === senderId)
  const receiver = devices.find((d) => d.device_id === receiverId)
  const bytes = new TextEncoder().encode(message).length

  const runSelection = async () => {
    setBusy(true); setError(''); setSelection(null); setTransmission(null); setStages(null)
    try {
      const data = await api('/api/select', {
        method: 'POST',
        body: JSON.stringify({ sender_id: senderId, receiver_id: receiverId, message }),
      })
      setSelection(data)
    } catch (e) {
      setError(e.message)
      setSelection(null)
    } finally { setBusy(false) }
  }

  const transmit = async () => {
    if (!selection) return
    setSending(true); setError(''); setStages(null)
    try {
      const data = await api('/api/transmit/detailed', {
        method: 'POST',
        body: JSON.stringify({
          sender_id: senderId,
          receiver_id: receiverId,
          message,
          profile_id: selection.winning_profile.profile_id,
          experiment_id: selection.experiment_id,
        }),
      })
      setStages(data)
      setTransmission(data)
    } catch (e) {
      // Fallback to simple transmit if detailed is unavailable
      try {
        const fbData = await api('/api/transmit', {
          method: 'POST',
          body: JSON.stringify({
            sender_id: senderId,
            receiver_id: receiverId,
            message,
            profile_id: selection.winning_profile.profile_id,
            experiment_id: selection.experiment_id,
          }),
        })
        setTransmission(fbData)
      } catch (fbErr) {
        setError(e.message || fbErr.message)
      }
    } finally { setSending(false) }
  }

  return (
    <div className="page-grid">
      <section className="workspace">
        <div className="hero-card">
          <div>
            <div className="hero-kicker"><Sparkles size={15} /> Adaptive decision engine</div>
            <h1>Adaptive Cryptographic Selection</h1>
            <p>Compare IoT device constraints and benchmark evidence to select a compatible, efficient cryptographic profile.</p>
          </div>
          <div className="flow">
            <span><Cpu size={17} /> Devices</span><ChevronRight size={16} />
            <span><Database size={17} /> Evidence</span><ChevronRight size={16} />
            <span><Gauge size={17} /> Score</span><ChevronRight size={16} />
            <span className="flow-accent"><LockKeyhole size={17} /> Secure</span>
          </div>
        </div>

        <div className="panel input-panel">
          <div className="panel-heading">
            <div><span className="section-number">01</span><div><h2>Configure experiment</h2><p>Select endpoints and the payload to protect.</p></div></div>
            <Badge tone={health?.status === 'ok' ? 'good' : 'warning'}>{health?.database || 'checking DB'}</Badge>
          </div>

          <div className="form-grid">
            <label>Sender device<select value={senderId} onChange={(e) => { setSenderId(e.target.value); setSelection(null); setError(''); setTransmission(null); setStages(null) }}>{devices.map(d => <option value={d.device_id} key={d.device_id}>{d.name}</option>)}</select></label>
            <label>Receiver device<select value={receiverId} onChange={(e) => { setReceiverId(e.target.value); setSelection(null); setError(''); setTransmission(null); setStages(null) }}>{devices.map(d => <option value={d.device_id} key={d.device_id}>{d.name}</option>)}</select></label>
          </div>

          <div className="device-pair">
            <DevicePreview label="Device A · sender" device={sender} />
            <div className="pair-arrow"><ArrowRight size={20} /></div>
            <DevicePreview label="Device B · receiver" device={receiver} />
          </div>

          <label className="message-field">Payload<textarea rows="4" value={message} onChange={(e) => { setMessage(e.target.value); setSelection(null); setError(''); setTransmission(null); setStages(null) }} /><span className="byte-counter">{bytes} UTF-8 bytes</span></label>

          <button className="primary" onClick={runSelection} disabled={busy || !senderId || !receiverId || senderId === receiverId}>
            {busy ? <><RefreshCw className="spin" size={18} /> Evaluating profiles…</> : <><Sparkles size={18} /> Analyze & select profile</>}
          </button>
          {senderId === receiverId && <div className="inline-warning"><CircleAlert size={16} /> Pick two different devices.</div>}
          {error && <SelectionFailure message={error} sender={sender} receiver={receiver} />}
        </div>

        {selection && (
          <>
            <div className="result-hero">
              <div className="result-icon"><ShieldCheck size={28} /></div>
              <div className="result-copy">
                <span className="eyebrow">Selected profile</span>
                <h2>{selection.winning_profile.profile_id} · {selection.winning_profile.name}</h2>
                <p>{selection.selection_reason}</p>
                <div className="result-badges">
                  <Badge tone="good">{selection.winning_profile.security_level} security</Badge>
                  <Badge>{profileFamily(selection.winning_profile)}</Badge>
                  <Badge>{selection.winning_profile.symmetric_encryption.algorithm} {selection.winning_profile.symmetric_encryption.key_size_bits}</Badge>
                  <Badge tone={selection.fallback_used ? 'warning' : 'neutral'}>{selection.fallback_used ? 'fallback' : 'normal selection'}</Badge>
                  {selection.is_demonstration_mode && <Badge tone="warning">estimated benchmark evidence</Badge>}
                </div>
              </div>
              <div className="score-block"><small>weighted score</small><strong>{Number(selection.winning_score).toFixed(4)}</strong><span>lower is better</span></div>
            </div>

            <div className="analysis-grid">
              <div className="panel">
                <div className="panel-heading compact"><div><span className="section-number">02</span><div><h2>Adaptive Weights</h2><p>Pressure automatically shifts the optimization objective.</p></div></div></div>
                <WeightBars weights={selection.dynamic_weights} pressures={selection.constraint_pressures} />
              </div>
              <div className="panel">
                <div className="panel-heading compact"><div><span className="section-number">03</span><div><h2>Constraints</h2><p>The stricter endpoint requirement applies.</p></div></div></div>
                <div className="constraint-grid">
                  <Metric icon={HardDrive} label="Memory limit" value={fmtRam(selection.combined_constraints.memory_limit_kb)} />
                  <Metric icon={Gauge} label="Latency limit" value={`${selection.combined_constraints.latency_limit_ms} ms`} />
                  <Metric icon={Network} label="Packet limit" value={`${selection.combined_constraints.packet_limit_bytes} B`} />
                  <Metric icon={ShieldCheck} label="Required security" value={selection.combined_constraints.required_security} />
                </div>
              </div>
            </div>

            <div className="panel">
              <div className="panel-heading compact"><div><span className="section-number">04</span><div><h2>Profile Decision</h2><p>Compatibility checks, performance estimates and selection scores for each profile.</p></div></div></div>
              <div className="candidate-list">
                {selection.candidate_details.map(item => <CandidateCard item={item} selectedId={selection.winning_profile.profile_id} key={item.profile_id} />)}
              </div>
            </div>

            <div className="transmit-card">
              <div><Radio size={22} /><div><h3>Ready for secure transmission</h3><p>Uses the selected profile over your existing framed TCP protocol on port 5000.</p></div></div>
              <button className="secondary" onClick={transmit} disabled={sending}>{sending ? <><RefreshCw className="spin" size={17} /> Sending…</> : <><Send size={17} /> Transmit securely</>}</button>
            </div>

            {sending && (
              <div className="panel" style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '18px 20px', border: '1px solid rgba(85,224,179,0.3)', background: 'rgba(85,224,179,0.04)', borderRadius: 14 }}>
                <RefreshCw className="spin" size={20} style={{ color: 'var(--accent)' }} />
                <div>
                  <h4 style={{ margin: '0 0 2px', fontSize: 13, color: 'var(--text)' }}>Executing cryptographic transmission...</h4>
                  <p style={{ margin: 0, fontSize: 11, color: 'var(--muted)' }}>
                    Generating keys, computing authenticated AES-GCM encryption, transmitting payload via TCP port 5000, and performing receiver verification.
                  </p>
                </div>
              </div>
            )}

            {stages && <TransmissionTimeline data={stages} />}

            {!stages && transmission && (
              <div className="success-box">
                <CheckCircle2 size={18} />
                <div>
                  <strong>Transmission accepted.</strong>
                  <span>Integrity verification {transmission.message_recovered ? 'passed' : 'failed'} · {transmission.experiment_id}</span>
                </div>
              </div>
            )}
          </>
        )}
      </section>


    </div>
  )
}

function ProfilesTab({ profiles }) {
  return (
    <section className="content-page">
      <div className="page-title"><span className="eyebrow">Configuration catalog</span><h1>Cryptographic profiles</h1><p>Your selector compares complete suites, not isolated algorithms.</p></div>
      <div className="profile-grid">
        {profiles.map((p) => (
          <div className="profile-card" key={p.profile_id}>
            <div className="profile-id">{p.profile_id}</div>
            <div className="profile-card-head"><KeyRound size={20} /><Badge tone={p.security_level === 'high' ? 'good' : p.security_level === 'basic' ? 'warning' : 'neutral'}>{p.security_level}</Badge></div>
            <h2>{p.name}</h2>
            <div className="profile-spec"><span>Key establishment</span><strong>{profileFamily(p)}</strong></div>
            <div className="profile-spec"><span>Symmetric cipher</span><strong>{p.symmetric_encryption.algorithm} · {p.symmetric_encryption.key_size_bits}-bit</strong></div>
            <div className="profile-spec"><span>Minimum CPU</span><strong>{p.minimum_cpu_level}</strong></div>
            <div className="profile-spec"><span>Role</span><strong>{p.profile_id === 'C5' ? 'fallback only' : 'normal candidate'}</strong></div>
          </div>
        ))}
      </div>
    </section>
  )
}

function HistoryTab() {
  const [experiments, setExperiments] = useState([])
  const [traffic, setTraffic] = useState([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    Promise.all([api('/api/experiments?limit=15'), api('/api/traffic?limit=10')])
      .then(([e, t]) => { setExperiments(e); setTraffic(t) })
      .finally(() => setLoading(false))
  }, [])
  const trafficByExp = useMemo(() => Object.fromEntries(traffic.map(t => [t.experiment_id, t])), [traffic])
  return (
    <section className="content-page">
      <div className="page-title"><span className="eyebrow">Recorded evidence</span><h1>Experiment history</h1><p>Selection decisions and post-transmission traffic observations in one view.</p></div>
      <div className="panel table-panel">
        {loading ? <div className="loading-line"><RefreshCw className="spin" size={18} /> Loading records…</div> : (
          <div className="history-list">
            {experiments.map((e) => {
              const t = trafficByExp[e.experiment_id]
              const a = t?.traffic_analysis
              return (
                <div className="history-row" key={e._id || e.experiment_id}>
                  <div className="history-status">{e.status === 'completed' || e.status === 'selected' ? <CheckCircle2 size={18} /> : e.status === 'failed' ? <XCircle size={18} /> : <Activity size={18} />}</div>
                  <div className="history-main"><strong>{e.experiment_id}</strong><span>{e.sender_name || e.sender_id || e.device_a_id || '—'} <ArrowRight size={12} /> {e.receiver_name || e.receiver_id || e.device_b_id || '—'}</span></div>
                  <div><small>profile</small><strong>{e.selected_profile_id || e.selected_profile || t?.profile_id || '—'}</strong></div>
                  <div><small>payload</small><strong>{e.message_size_bytes != null ? `${e.message_size_bytes} B` : '—'}</strong></div>
                  <div><small>traffic</small><strong>{a?.total_packets != null ? `${a.total_packets} pkts` : t?.capture_status || '—'}</strong></div>
                  <Badge tone={e.fallback_used ? 'warning' : e.status === 'failed' ? 'bad' : 'neutral'}>{e.fallback_used ? 'fallback' : e.status || 'recorded'}</Badge>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </section>
  )
}

export default function App() {
  const [tab, setTab] = useState('experiment')
  const [devices, setDevices] = useState([])
  const [profiles, setProfiles] = useState([])
  const [health, setHealth] = useState(null)
  const [bootError, setBootError] = useState('')

  useEffect(() => {
    Promise.all([api('/api/devices'), api('/api/profiles'), api('/api/health')])
      .then(([d, p, h]) => { setDevices(d); setProfiles(p); setHealth(h) })
      .catch((e) => setBootError(e.message))
  }, [])

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand"><div className="brand-mark"><LockKeyhole size={20} /></div><div><strong>Adaptive Crypto</strong><span>IoT Control Plane</span></div></div>
        <nav>
          <button className={tab === 'experiment' ? 'active' : ''} onClick={() => setTab('experiment')}><Activity size={16} /> Experiment</button>
          <button className={tab === 'traffic' ? 'active' : ''} onClick={() => setTab('traffic')}><Radio size={16} /> Traffic</button>
          <button className={tab === 'profiles' ? 'active' : ''} onClick={() => setTab('profiles')}><KeyRound size={16} /> Profiles</button>
          <button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}><History size={16} /> History</button>
        </nav>
        <div className={`api-pill ${health?.status === 'ok' ? 'online' : ''}`}><span /> API {health?.status === 'ok' ? 'online' : 'checking'}</div>
      </header>

      <main>
        {bootError && <div className="boot-error"><CircleAlert size={18} /> {bootError}. Make sure FastAPI and MongoDB are running.</div>}
        {tab === 'experiment' && <ExperimentTab devices={devices} health={health} />}
        {tab === 'profiles' && <ProfilesTab profiles={profiles} />}
        {tab === 'history' && <HistoryTab />}
        {tab === 'traffic' && <TrafficTab />}
      </main>

      <footer><span>Adaptive Cryptographic Algorithm Selection for Resource-Constrained IoT</span><span>Device constraints · benchmark evidence · explainable selection · traffic analysis</span></footer>
    </div>
  )
}
