/**
 * QNXGuard — Real-Time Microkernel Channel Circuit Breaker
 * 
 * Enforces fail-closed channel isolation in QNX 8.0 RTOS.
 * Instantly severs malicious IPC connections (simulating ChannelDestroy / MsgError)
 * in sub-millisecond real-time latency to protect mission-critical threads.
 */

const STATES = {
  ARMED: 'ARMED',
  THROTTLED: 'THROTTLED',
  ISOLATED_LOCK: 'ISOLATED_LOCK'
};

class QNXCircuitBreaker {
  constructor(options = {}) {
    this.state = STATES.ARMED;
    this.isolatedChannels = new Set();
    this.isolatedPids = new Set();
    this.rateLimitWindowMs = options.rateLimitWindowMs || 1000; // 1 second
    this.maxFramesPerSec = options.maxFramesPerSec || 200;      // 200 msgs/sec
    this.history = [];
    this.adminToken = options.adminToken || 'QNXGUARD_ROOT_OVERRIDE_KEY_2026';
    this.tripReason = null;
    this.trippedAt = null;
  }

  /**
   * Evaluate whether an IPC message is authorized to pass through the microkernel channel.
   * @param {number} channelId 
   * @param {number} senderPid 
   * @returns {{ authorized: boolean, state: string, reason?: string }}
   */
  evaluate(channelId, senderPid) {
    // 1. Check if channel or PID is already isolated
    if (this.isolatedChannels.has(channelId)) {
      return {
        authorized: false,
        state: STATES.ISOLATED_LOCK,
        reason: `Channel #${channelId} is in ISOLATED_LOCK. IPC message rejected with EBADF.`
      };
    }

    if (this.isolatedPids.has(senderPid)) {
      return {
        authorized: false,
        state: STATES.ISOLATED_LOCK,
        reason: `Process PID #${senderPid} is quarantined. IPC message rejected with EACCES.`
      };
    }

    if (this.state === STATES.ISOLATED_LOCK) {
      return {
        authorized: false,
        state: this.state,
        reason: `Global RTOS circuit breaker is ISOLATED_LOCK: ${this.tripReason}`
      };
    }

    // 2. High-Frequency Channel Flooding (DoS) Check
    const now = Date.now();
    const recent = this.history.filter(h => h.channelId === channelId && now - h.timestamp < this.rateLimitWindowMs);
    if (recent.length >= this.maxFramesPerSec) {
      this.isolateChannel(channelId, `IPC Channel flooding DoS detected: ${recent.length} msgs/sec exceeds ${this.maxFramesPerSec}`);
      return {
        authorized: false,
        state: STATES.ISOLATED_LOCK,
        reason: `Channel #${channelId} isolated due to DoS rate breach.`
      };
    }

    return {
      authorized: true,
      state: this.state
    };
  }

  commitMessage(channelId, senderPid) {
    this.history.push({
      timestamp: Date.now(),
      channelId,
      senderPid
    });
    // Keep sliding window trim
    if (this.history.length > 500) {
      this.history.shift();
    }
  }

  isolateChannel(channelId, reason) {
    this.isolatedChannels.add(channelId);
    this.state = STATES.ISOLATED_LOCK;
    this.tripReason = reason;
    this.trippedAt = Date.now();
  }

  quarantinePid(senderPid, reason) {
    this.isolatedPids.add(senderPid);
    this.state = STATES.ISOLATED_LOCK;
    this.tripReason = reason;
    this.trippedAt = Date.now();
  }

  reset(token) {
    if (token !== this.adminToken) {
      throw new Error('CircuitSecurityError: Invalid administrative root token');
    }
    this.state = STATES.ARMED;
    this.isolatedChannels.clear();
    this.isolatedPids.clear();
    this.tripReason = null;
    this.trippedAt = null;
    return { success: true, state: this.state };
  }
}

module.exports = { QNXCircuitBreaker, STATES };
