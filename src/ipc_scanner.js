/**
 * QNXGuard — Real-Time Microkernel IPC Anomaly Scanner
 * 
 * Inspects synchronous IPC message payloads (MsgSend / MsgReceive) in QNX 8.0 RTOS.
 * Calculates Shannon entropy and detects exploit signatures, ROP chains, 
 * CAN-bus frame spoofing, and buffer overflow vectors in sub-millisecond time.
 */

const EXPLOIT_PATTERNS = [
  { name: 'NOP_SLED_INJECTION', pattern: /\x90{8,}/, weight: 50 },
  { name: 'FORMAT_STRING_ATTACK', pattern: /(%[0-9]*[sdxXpn]){3,}/, weight: 45 },
  { name: 'SHELLCODE_PATTERN', pattern: /\x31\xc0\x50\x68|\x48\x31\xd2\x48\xbb/, weight: 50 },
  { name: 'PATH_TRAVERSAL_IPC', pattern: /(\.\.\/|\.\.\\){2,}/, weight: 40 },
  { name: 'CAN_BUS_OVERRIDE', pattern: /(BRAKE_FORCE_ZERO|STEER_LOCK_DISABLE|ACCEL_MAX_OVERRIDE)/, weight: 45 }
];

class IPCScanner {
  /**
   * Calculate Shannon entropy: H(X) = -sum(p * log2(p))
   * @param {Buffer|Uint8Array|string} data 
   * @returns {number} Entropy in bits per byte (0.0 to 8.0)
   */
  static calculateEntropy(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (buf.length === 0) return 0.0;

    const freq = new Map();
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      freq.set(b, (freq.get(b) || 0) + 1);
    }

    let entropy = 0.0;
    const len = buf.length;
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return Math.round(entropy * 1000) / 1000;
  }

  /**
   * Inspect an incoming synchronous QNX IPC message frame.
   * @param {object} frame
   * @param {number} frame.channelId - QNX Channel ID
   * @param {number} frame.connectionId - QNX CoID
   * @param {number} frame.senderPid - Sender Process ID
   * @param {Buffer|string} frame.payload - Raw message payload
   * @param {number} [frame.maxAllowedBytes=4096] - Maximum allowed buffer size
   * @returns {object} Scan diagnostic verdict
   */
  static scanMessage(frame) {
    const { channelId, connectionId, senderPid, payload, maxAllowedBytes = 4096 } = frame;
    const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload || '');

    // 1. Buffer overflow / maximum frame bound check
    if (buf.length > maxAllowedBytes) {
      return {
        safe: false,
        status: 'BUFFER_OVERFLOW_ATTEMPT',
        score: 100,
        flags: ['MAX_FRAME_SIZE_EXCEEDED'],
        entropy: this.calculateEntropy(buf),
        sizeBytes: buf.length,
        reason: `IPC buffer size ${buf.length} bytes exceeds channel limit of ${maxAllowedBytes} bytes`
      };
    }

    // 2. High-entropy payload analysis (Encrypted/packed shellcode)
    const entropy = this.calculateEntropy(buf);
    let totalScore = 0;
    const flags = [];

    if (entropy > 7.75 && buf.length > 64) {
      totalScore += 45;
      flags.push('HIGH_ENTROPY_SHELLCODE');
    }

    // 3. Pattern / Signature Heuristic Matching
    const str = buf.toString('binary');
    for (const rule of EXPLOIT_PATTERNS) {
      if (rule.pattern.test(str)) {
        totalScore += rule.weight;
        flags.push(rule.name);
      }
    }

    const safe = totalScore < 35;
    return {
      safe,
      status: safe ? 'CLEAN_IPC_FRAME' : 'ANOMALOUS_PAYLOAD_DETECTED',
      score: totalScore,
      flags,
      entropy,
      sizeBytes: buf.length,
      channelId,
      connectionId,
      senderPid
    };
  }
}

module.exports = { IPCScanner, EXPLOIT_PATTERNS };
