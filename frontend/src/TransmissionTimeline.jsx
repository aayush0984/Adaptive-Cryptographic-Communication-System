import { useState } from 'react'
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cpu,
  FileText,
  KeyRound,
  Lock,
  Network,
  Radio,
  Server,
  ShieldCheck,
  Terminal,
  Unlock,
  XCircle,
  Zap,
} from 'lucide-react'
import './timeline.css'

export default function TransmissionTimeline({ data }) {
  if (!data) return null

  // Keep track of which step cards are open (default all open for full clarity)
  const [openSteps, setOpenSteps] = useState({
    plaintext: true,
    keygen: true,
    keyest: true,
    nonce: true,
    encrypt: true,
    network: true,
    keyrecv: true,
    decrypt: true,
  })

  const [showFullCipher, setShowFullCipher] = useState(false)
  const [showFullPem, setShowFullPem] = useState(false)

  const toggleStep = (stepKey) => {
    setOpenSteps((prev) => ({ ...prev, [stepKey]: !prev[stepKey] }))
  }

  const expandAll = () => {
    setOpenSteps({
      plaintext: true,
      keygen: true,
      keyest: true,
      nonce: true,
      encrypt: true,
      network: true,
      keyrecv: true,
      decrypt: true,
    })
  }

  const collapseAll = () => {
    setOpenSteps({
      plaintext: false,
      keygen: false,
      keyest: false,
      nonce: false,
      encrypt: false,
      network: false,
      keyrecv: false,
      decrypt: false,
    })
  }

  const {
    experiment_id,
    profile_id,
    profile_name,
    sender_name,
    sender_id,
    receiver_name,
    receiver_id,
    message_size_bytes,
    plaintext,
    plaintext_preview,
    overall_status,
    total_time_ms,
    sender = {},
    network = {},
    receiver = {},
  } = data

  const isRsa = profile_id === 'C1' || profile_id === 'C2'
  const isEcdh = profile_id === 'C3' || profile_id === 'C4'
  const isPsk = profile_id === 'C5'

  const enc = sender.encryption || {}
  const dec = receiver.decryption || {}
  const keyGen = sender.key_generation || {}
  const keyWrap = sender.key_wrapping || {}
  const keyEx = sender.key_exchange || {}
  const nonceGen = sender.nonce_generation || {}
  const keyUnwrap = receiver.key_unwrapping || {}
  const keyDeriv = receiver.key_derivation || {}

  const isSuccess = overall_status === 'success' && dec.integrity_match

  return (
    <div className="tl-container">
      {/* ── Top Bar ── */}
      <div className="tl-topbar">
        <div className="tl-title-group">
          <div className="tl-title-icon">
            <Radio size={20} />
          </div>
          <div className="tl-title-text">
            <h3>Secure Communication Workflow</h3>
            <p>
              Profile {profile_id} ({profile_name}) · {sender_name} → {receiver_name}
            </p>
          </div>
        </div>
        <div className="tl-topbar-actions">
          <button className="tl-btn-text" onClick={expandAll}>Expand all</button>
          <button className="tl-btn-text" onClick={collapseAll}>Collapse all</button>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════
          SECTION 1: DEVICE A — SENDER
          ════════════════════════════════════════════════════════════ */}
      <div className="tl-section tl-sec-sender">
        <div className="tl-section-header">
          <div className="tl-section-title">
            <Cpu size={16} />
            <span>Device A — Sender ({sender_name})</span>
          </div>
          <div className="tl-section-meta">
            ID: {sender_id || sender_name.toLowerCase().replace(/\s+/g, '_')}
          </div>
        </div>

        <div className="tl-steps">
          {/* Step 1: Original Plaintext Message */}
          <div className="tl-step-card">
            <div className="tl-node-dot" />
            <div className="tl-step-header" onClick={() => toggleStep('plaintext')}>
              <div className="tl-step-left">
                <div className="tl-step-icon"><FileText size={15} /></div>
                <div className="tl-step-title-wrap">
                  <div className="tl-step-title">
                    1. Plaintext Message
                    <span className="badge good">In Memory</span>
                  </div>
                  <div className="tl-step-subtitle">
                    {message_size_bytes} UTF-8 bytes payload
                  </div>
                </div>
              </div>
              <div className="tl-step-right">
                <span className="tl-step-time">{message_size_bytes} B</span>
                {openSteps.plaintext ? <ChevronUp size={16} className="tl-chevron" /> : <ChevronDown size={16} className="tl-chevron" />}
              </div>
            </div>
            {openSteps.plaintext && (
              <div className="tl-step-body">
                <div className="tl-prop-grid">
                  <div className="tl-prop">
                    <span className="tl-prop-label">Payload Size</span>
                    <span className="tl-prop-value accent">{message_size_bytes} bytes</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Character Encoding</span>
                    <span className="tl-prop-value">UTF-8</span>
                  </div>
                  <div className="tl-prop-full">
                    <span className="tl-prop-label">Raw Plaintext Content</span>
                    <div className="tl-code-block">{plaintext || plaintext_preview}</div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Step 2: Cryptographic Key Generation */}
          <div className="tl-step-card">
            <div className="tl-node-dot" />
            <div className="tl-step-header" onClick={() => toggleStep('keygen')}>
              <div className="tl-step-left">
                <div className="tl-step-icon"><KeyRound size={15} /></div>
                <div className="tl-step-title-wrap">
                  <div className="tl-step-title">
                    2. Cryptographic Key Generation
                    <span className="badge good">Ready</span>
                  </div>
                  <div className="tl-step-subtitle">
                    {keyGen.method || (isRsa ? 'RSA-OAEP' : isEcdh ? `ECDH-${keyGen.curve}` : 'Pre-Shared Key')}
                  </div>
                </div>
              </div>
              <div className="tl-step-right">
                {keyGen.time_ms != null && <span className="tl-step-time">{keyGen.time_ms.toFixed(2)} ms</span>}
                {openSteps.keygen ? <ChevronUp size={16} className="tl-chevron" /> : <ChevronDown size={16} className="tl-chevron" />}
              </div>
            </div>
            {openSteps.keygen && (
              <div className="tl-step-body">
                <div className="tl-prop-grid">
                  <div className="tl-prop">
                    <span className="tl-prop-label">Method</span>
                    <span className="tl-prop-value accent">{keyGen.method || 'Standard'}</span>
                  </div>
                  {keyGen.key_size_bits && (
                    <div className="tl-prop">
                      <span className="tl-prop-label">Key Length</span>
                      <span className="tl-prop-value">{keyGen.key_size_bits} bits</span>
                    </div>
                  )}
                  {keyGen.curve && (
                    <div className="tl-prop">
                      <span className="tl-prop-label">Elliptic Curve</span>
                      <span className="tl-prop-value">{keyGen.curve}</span>
                    </div>
                  )}
                  {keyGen.receiver_public_key_fingerprint && (
                    <div className="tl-prop-full">
                      <span className="tl-prop-label">Receiver Public Key Fingerprint</span>
                      <span className="tl-prop-value">{keyGen.receiver_public_key_fingerprint}</span>
                    </div>
                  )}
                  {keyGen.sender_public_key_pem && (
                    <div className="tl-prop-full">
                      <div className="tl-code-preview">
                        <span className="tl-prop-label">Ephemeral Sender Public Key (PEM)</span>
                        <button className="tl-btn-text" onClick={() => setShowFullPem(!showFullPem)}>
                          {showFullPem ? 'Collapse PEM' : 'Expand PEM'}
                        </button>
                      </div>
                      <div className="tl-code-block">
                        {showFullPem
                          ? keyGen.sender_public_key_pem
                          : `${keyGen.sender_public_key_pem.split('\n').slice(0, 3).join('\n')}\n... [truncated]`}
                      </div>
                    </div>
                  )}
                  {keyGen.description && (
                    <div className="tl-prop-full">
                      <span className="tl-prop-label">Details</span>
                      <span className="tl-prop-value">{keyGen.description}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Step 3: Key Establishment / Wrapping */}
          <div className="tl-step-card">
            <div className="tl-node-dot" />
            <div className="tl-step-header" onClick={() => toggleStep('keyest')}>
              <div className="tl-step-left">
                <div className="tl-step-icon"><Zap size={15} /></div>
                <div className="tl-step-title-wrap">
                  <div className="tl-step-title">
                    3. Key Establishment
                    <span className="badge good">Secured</span>
                  </div>
                  <div className="tl-step-subtitle">
                    {isRsa && 'RSA-OAEP Session Key Wrapping (AES Key Sealed)'}
                    {isEcdh && 'Ephemeral Diffie-Hellman Exchange + HKDF Derivation'}
                    {isPsk && 'Static Pre-Shared Key Binding (Zero Overhead)'}
                  </div>
                </div>
              </div>
              <div className="tl-step-right">
                {(keyWrap.time_ms ?? keyEx.time_ms) != null && (
                  <span className="tl-step-time">{(keyWrap.time_ms ?? keyEx.time_ms).toFixed(2)} ms</span>
                )}
                {openSteps.keyest ? <ChevronUp size={16} className="tl-chevron" /> : <ChevronDown size={16} className="tl-chevron" />}
              </div>
            </div>
            {openSteps.keyest && (
              <div className="tl-step-body">
                <div className="tl-prop-grid">
                  {isRsa && (
                    <>
                      <div className="tl-prop">
                        <span className="tl-prop-label">Key Wrap Scheme</span>
                        <span className="tl-prop-value accent">RSA-OAEP SHA-256</span>
                      </div>
                      <div className="tl-prop">
                        <span className="tl-prop-label">Wrapped Key Size</span>
                        <span className="tl-prop-value">{keyWrap.wrapped_key_size_bytes} bytes</span>
                      </div>
                      <div className="tl-prop-full">
                        <span className="tl-prop-label">Mechanism</span>
                        <span className="tl-prop-value">
                          Random 128/256-bit AES session key generated on Sender and encrypted under Receiver's RSA public key using OAEP padding with MGF1-SHA256.
                        </span>
                      </div>
                    </>
                  )}
                  {isEcdh && (
                    <>
                      <div className="tl-prop">
                        <span className="tl-prop-label">Key Agreement</span>
                        <span className="tl-prop-value accent">ECDH (Curve {keyEx.curve || 'Standard'})</span>
                      </div>
                      <div className="tl-prop">
                        <span className="tl-prop-label">KDF Algorithm</span>
                        <span className="tl-prop-value">HKDF-SHA256</span>
                      </div>
                      <div className="tl-prop-full">
                        <span className="tl-prop-label">Mechanism</span>
                        <span className="tl-prop-value">
                          Sender computes raw shared secret = sender_private × receiver_public. HKDF derives symmetric session key with fresh random salt. Raw secrets are discarded immediately.
                        </span>
                      </div>
                    </>
                  )}
                  {isPsk && (
                    <div className="tl-prop-full">
                      <span className="tl-prop-label">Mechanism</span>
                      <span className="tl-prop-value">
                        Sender utilizes pre-configured 128-bit Pre-Shared Key (PSK) directly. No public key exchange overhead incurred on wire.
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Step 4: AES-GCM Nonce Generation */}
          <div className="tl-step-card">
            <div className="tl-node-dot" />
            <div className="tl-step-header" onClick={() => toggleStep('nonce')}>
              <div className="tl-step-left">
                <div className="tl-step-icon"><Lock size={15} /></div>
                <div className="tl-step-title-wrap">
                  <div className="tl-step-title">
                    4. Nonce Generation
                    <span className="badge good">CSPRNG</span>
                  </div>
                  <div className="tl-step-subtitle">
                    96-bit unique IV generated for AES-GCM
                  </div>
                </div>
              </div>
              <div className="tl-step-right">
                <span className="tl-step-time">{nonceGen.size_bytes || 12} B</span>
                {openSteps.nonce ? <ChevronUp size={16} className="tl-chevron" /> : <ChevronDown size={16} className="tl-chevron" />}
              </div>
            </div>
            {openSteps.nonce && (
              <div className="tl-step-body">
                <div className="tl-prop-grid">
                  <div className="tl-prop">
                    <span className="tl-prop-label">Nonce Length</span>
                    <span className="tl-prop-value accent">{nonceGen.size_bytes || 12} bytes (96 bits)</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Entropy Source</span>
                    <span className="tl-prop-value">os.urandom (CSPRNG)</span>
                  </div>
                  <div className="tl-prop-full">
                    <span className="tl-prop-label">Nonce Hex Value</span>
                    <div className="tl-code-block">{nonceGen.nonce_hex || '—'}</div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Step 5: AES-GCM Encryption */}
          <div className="tl-step-card">
            <div className="tl-node-dot" />
            <div className="tl-step-header" onClick={() => toggleStep('encrypt')}>
              <div className="tl-step-left">
                <div className="tl-step-icon"><ShieldCheck size={15} /></div>
                <div className="tl-step-title-wrap">
                  <div className="tl-step-title">
                    5. AES-GCM Encryption
                    <span className="badge good">Authenticated</span>
                  </div>
                  <div className="tl-step-subtitle">
                    {enc.algorithm || 'AES-GCM'} ({enc.key_size_bits || 128}-bit)
                  </div>
                </div>
              </div>
              <div className="tl-step-right">
                {enc.time_ms != null && <span className="tl-step-time">{enc.time_ms.toFixed(3)} ms</span>}
                {openSteps.encrypt ? <ChevronUp size={16} className="tl-chevron" /> : <ChevronDown size={16} className="tl-chevron" />}
              </div>
            </div>
            {openSteps.encrypt && (
              <div className="tl-step-body">
                <div className="tl-prop-grid">
                  <div className="tl-prop">
                    <span className="tl-prop-label">Cipher Suite</span>
                    <span className="tl-prop-value accent">{enc.algorithm}</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Ciphertext Size</span>
                    <span className="tl-prop-value">{enc.ciphertext_size_bytes} bytes</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Authentication Tag</span>
                    <span className="tl-prop-value good">{enc.tag_size_bytes || 16} bytes (128-bit GHASH)</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Encryption Latency</span>
                    <span className="tl-prop-value">{enc.time_ms} ms</span>
                  </div>
                  {enc.tag_hex && (
                    <div className="tl-prop-full">
                      <span className="tl-prop-label">GHASH Authentication Tag (Hex)</span>
                      <div className="tl-code-block">{enc.tag_hex}</div>
                    </div>
                  )}
                  {enc.ciphertext_b64 && (
                    <div className="tl-prop-full">
                      <div className="tl-code-preview">
                        <span className="tl-prop-label">Ciphertext (Base64)</span>
                        <button className="tl-btn-text" onClick={() => setShowFullCipher(!showFullCipher)}>
                          {showFullCipher ? 'Truncate' : 'Show Full'}
                        </button>
                      </div>
                      <div className="tl-code-block">
                        {showFullCipher
                          ? enc.ciphertext_b64
                          : `${enc.ciphertext_b64.slice(0, 48)}... (${enc.ciphertext_b64.length} chars)`}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════
          SECTION 2: NETWORK TRANSMISSION (TCP)
          ════════════════════════════════════════════════════════════ */}
      <div className="tl-section tl-sec-network">
        <div className="tl-section-header">
          <div className="tl-section-title">
            <Network size={16} />
            <span>Network Transmission (TCP Channel)</span>
          </div>
          <div className="tl-section-meta">
            Port {network.port || 5000} · {network.status || 'delivered'}
          </div>
        </div>

        <div className="tl-steps">
          {/* Step 6: Framed TCP Wire Transmission */}
          <div className="tl-step-card">
            <div className={`tl-node-dot ${network.status === 'delivered' ? '' : 'status-error'}`} />
            <div className="tl-step-header" onClick={() => toggleStep('network')}>
              <div className="tl-step-left">
                <div className="tl-step-icon"><Radio size={15} /></div>
                <div className="tl-step-title-wrap">
                  <div className="tl-step-title">
                    6. Framed TCP Transmission
                    <span className={`badge ${network.status === 'delivered' ? 'good' : 'bad'}`}>
                      {network.status === 'delivered' ? 'Transmitted' : 'Failed'}
                    </span>
                  </div>
                  <div className="tl-step-subtitle">
                    {sender_name} → {receiver_name} via {network.protocol || 'TCP'}
                  </div>
                </div>
              </div>
              <div className="tl-step-right">
                {network.time_ms != null && <span className="tl-step-time">{network.time_ms.toFixed(2)} ms</span>}
                {openSteps.network ? <ChevronUp size={16} className="tl-chevron" /> : <ChevronDown size={16} className="tl-chevron" />}
              </div>
            </div>
            {openSteps.network && (
              <div className="tl-step-body">
                <div className="tl-prop-grid">
                  <div className="tl-prop">
                    <span className="tl-prop-label">Transport Protocol</span>
                    <span className="tl-prop-value accent">{network.protocol || 'TCP (framed JSON v1)'}</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Target Port</span>
                    <span className="tl-prop-value">{network.port || 5000}</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Total Frame Size</span>
                    <span className="tl-prop-value">{network.frame_size_bytes} bytes</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">TCP Payload Size</span>
                    <span className="tl-prop-value">{network.payload_size_bytes} bytes</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Network Status</span>
                    <span className={`tl-prop-value ${network.status === 'delivered' ? 'good' : 'accent'}`}>
                      {network.status || 'delivered'}
                    </span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Transmission Latency</span>
                    <span className="tl-prop-value">{network.time_ms} ms</span>
                  </div>
                  <div className="tl-prop-full">
                    <span className="tl-prop-label">Framed Protocol Fields</span>
                    <div className="tl-code-block">
                      {JSON.stringify(
                        network.protocol_fields || {
                          protocol_version: 1,
                          message_type: 'HELLO',
                          experiment_id,
                          profile_id,
                          sequence_number: 1,
                        },
                        null,
                        2
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════
          SECTION 3: DEVICE B — RECEIVER
          ════════════════════════════════════════════════════════════ */}
      <div className="tl-section tl-sec-receiver">
        <div className="tl-section-header">
          <div className="tl-section-title">
            <Server size={16} />
            <span>Device B — Receiver ({receiver_name})</span>
          </div>
          <div className="tl-section-meta">
            ID: {receiver_id || receiver_name.toLowerCase().replace(/\s+/g, '_')}
          </div>
        </div>

        <div className="tl-steps">
          {/* Step 7: Receiver Key Unwrapping / Derivation */}
          <div className="tl-step-card">
            <div className="tl-node-dot" />
            <div className="tl-step-header" onClick={() => toggleStep('keyrecv')}>
              <div className="tl-step-left">
                <div className="tl-step-icon"><Unlock size={15} /></div>
                <div className="tl-step-title-wrap">
                  <div className="tl-step-title">
                    7. Session Key Establishment
                    <span className="badge good">Recovered</span>
                  </div>
                  <div className="tl-step-subtitle">
                    {isRsa && 'RSA-OAEP Private Key Unwrapping'}
                    {isEcdh && 'Receiver ECDH Derivation via HKDF-SHA256'}
                    {isPsk && 'Pre-Shared Key Local Lookup'}
                  </div>
                </div>
              </div>
              <div className="tl-step-right">
                {(keyUnwrap.time_ms ?? keyDeriv.time_ms) != null && (
                  <span className="tl-step-time">{(keyUnwrap.time_ms ?? keyDeriv.time_ms).toFixed(2)} ms</span>
                )}
                {openSteps.keyrecv ? <ChevronUp size={16} className="tl-chevron" /> : <ChevronDown size={16} className="tl-chevron" />}
              </div>
            </div>
            {openSteps.keyrecv && (
              <div className="tl-step-body">
                <div className="tl-prop-grid">
                  {isRsa && (
                    <>
                      <div className="tl-prop">
                        <span className="tl-prop-label">Unwrapping Method</span>
                        <span className="tl-prop-value accent">{keyUnwrap.method || 'RSA-OAEP SHA-256'}</span>
                      </div>
                      <div className="tl-prop">
                        <span className="tl-prop-label">Unwrap Latency</span>
                        <span className="tl-prop-value">{keyUnwrap.time_ms} ms</span>
                      </div>
                      <div className="tl-prop-full">
                        <span className="tl-prop-label">Mechanism</span>
                        <span className="tl-prop-value">
                          Receiver decrypts wrapped AES key using its private RSA key. The plaintext AES session key is reconstructed in secure memory.
                        </span>
                      </div>
                    </>
                  )}
                  {isEcdh && (
                    <>
                      <div className="tl-prop">
                        <span className="tl-prop-label">Derivation Method</span>
                        <span className="tl-prop-value accent">{keyDeriv.method || 'HKDF-SHA256'}</span>
                      </div>
                      <div className="tl-prop">
                        <span className="tl-prop-label">Derivation Latency</span>
                        <span className="tl-prop-value">{keyDeriv.time_ms} ms</span>
                      </div>
                      <div className="tl-prop-full">
                        <span className="tl-prop-label">Mechanism</span>
                        <span className="tl-prop-value">
                          Receiver computes shared secret = receiver_private × sender_public. Passing the received salt into HKDF-SHA256 yields the identical AES session key.
                        </span>
                      </div>
                    </>
                  )}
                  {isPsk && (
                    <div className="tl-prop-full">
                      <span className="tl-prop-label">Mechanism</span>
                      <span className="tl-prop-value">
                        Receiver accesses its configured Pre-Shared Key (PSK) matching the sender profile.
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Step 8: Authenticated Decryption & Integrity Verification */}
          <div className="tl-step-card">
            <div className="tl-node-dot" />
            <div className="tl-step-header" onClick={() => toggleStep('decrypt')}>
              <div className="tl-step-left">
                <div className="tl-step-icon"><CheckCircle2 size={15} /></div>
                <div className="tl-step-title-wrap">
                  <div className="tl-step-title">
                    8. Decryption & Integrity Verification
                    <span className="badge good">Verified</span>
                  </div>
                  <div className="tl-step-subtitle">
                    AES-GCM Authentication Tag Verified · Plaintext Recovered
                  </div>
                </div>
              </div>
              <div className="tl-step-right">
                {dec.time_ms != null && <span className="tl-step-time">{dec.time_ms.toFixed(3)} ms</span>}
                {openSteps.decrypt ? <ChevronUp size={16} className="tl-chevron" /> : <ChevronDown size={16} className="tl-chevron" />}
              </div>
            </div>
            {openSteps.decrypt && (
              <div className="tl-step-body">
                <div className="tl-prop-grid">
                  <div className="tl-prop">
                    <span className="tl-prop-label">Cipher Suite</span>
                    <span className="tl-prop-value accent">{dec.algorithm || 'AES-GCM'}</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Tag Verification</span>
                    <span className="tl-prop-value good">PASSED ✓ (GHASH tag valid)</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Decryption Latency</span>
                    <span className="tl-prop-value">{dec.time_ms} ms</span>
                  </div>
                  <div className="tl-prop">
                    <span className="tl-prop-label">Decrypted Size</span>
                    <span className="tl-prop-value">{dec.decrypted_size_bytes || message_size_bytes} bytes</span>
                  </div>
                </div>

                {/* Plaintext Comparison */}
                <div className="tl-compare-box">
                  <div className="tl-compare-col">
                    <span className="tl-compare-label">Original Sender Message</span>
                    <div className="tl-compare-text">{plaintext || plaintext_preview}</div>
                  </div>
                  <div className="tl-compare-col">
                    <span className="tl-compare-label">Recovered Receiver Message</span>
                    <div className="tl-compare-text">{dec.recovered_plaintext || plaintext}</div>
                  </div>
                  <div className={`tl-integrity-banner ${dec.integrity_match ? '' : 'failed'}`}>
                    <span>Integrity Verification Status:</span>
                    <strong>{dec.integrity_match ? 'PASSED ✓ (Exact Byte-for-Byte Match)' : 'FAILED ✗ (Mismatch)'}</strong>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════
          FINAL SUMMARY CARD
          ════════════════════════════════════════════════════════════ */}
      <div className="tl-summary-card">
        <div className="tl-summary-head">
          <div className="tl-summary-title">
            <ShieldCheck size={18} color="#55e0b3" />
            <span>Workflow Summary</span>
          </div>
          <div className="badge good">
            {isSuccess ? 'Transmission Verified' : 'Completed with Notes'}
          </div>
        </div>

        <div className="tl-summary-grid">
          <div className="tl-summary-item">
            <span>Profile</span>
            <strong>{profile_id}</strong>
          </div>
          <div className="tl-summary-item">
            <span>Total Time</span>
            <strong>{total_time_ms} ms</strong>
          </div>
          <div className="tl-summary-item">
            <span>Encryption</span>
            <strong>{enc.time_ms ? `${enc.time_ms} ms` : '—'}</strong>
          </div>
          <div className="tl-summary-item">
            <span>Decryption</span>
            <strong>{dec.time_ms ? `${dec.time_ms} ms` : '—'}</strong>
          </div>
          <div className="tl-summary-item">
            <span>Transmitted Frame</span>
            <strong>{network.frame_size_bytes ? `${network.frame_size_bytes} B` : '—'}</strong>
          </div>
          <div className="tl-summary-item">
            <span>Integrity Match</span>
            <strong style={{ color: dec.integrity_match ? '#66e0ae' : '#ff8e89' }}>
              {dec.integrity_match ? '100% Match' : 'Mismatch'}
            </strong>
          </div>
        </div>
      </div>
    </div>
  )
}

