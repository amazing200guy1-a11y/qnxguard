/**
 * QNXGuard — Unified Microkernel Sentinel Engine
 */

const { IPCScanner } = require('./ipc_scanner');
const { QNXCircuitBreaker, STATES } = require('./circuit_breaker');
const { AuditLedger } = require('./audit_ledger');

class QNXSentinel {
  constructor(options = {}) {
    this.circuitBreaker = new QNXCircuitBreaker(options);
    this.auditLedger = new AuditLedger();
  }

  processMessage(frame) {
    const { channelId, senderPid, payload, connectionId = 1 } = frame;

    // 1. Circuit Breaker pre-evaluation
    const cbCheck = this.circuitBreaker.evaluate(channelId, senderPid);
    if (!cbCheck.authorized) {
      const block = this.auditLedger.seal('IPC_MESSAGE_REJECTED_ISOLATED', {
        channelId,
        senderPid,
        reason: cbCheck.reason
      });
      return {
        authorized: false,
        status: 'HALTED_BY_CIRCUIT_BREAKER',
        reason: cbCheck.reason,
        circuitState: cbCheck.state,
        auditBlock: block
      };
    }

    // 2. Shannon Entropy & Exploit Pattern Scanning
    const scan = IPCScanner.scanMessage({ channelId, connectionId, senderPid, payload });
    if (!scan.safe) {
      this.circuitBreaker.isolateChannel(channelId, `Exploit pattern detected: ${scan.flags.join(', ')}`);
      const block = this.auditLedger.seal('ANOMALOUS_IPC_INTERCEPTED', {
        channelId,
        senderPid,
        flags: scan.flags,
        score: scan.score,
        entropy: scan.entropy
      });
      return {
        authorized: false,
        status: 'INTERCEPTED_EXPLOIT_PAYLOAD',
        reason: `Microkernel anomaly intercepted. Flags: ${scan.flags.join(', ')}`,
        circuitState: this.circuitBreaker.state,
        auditBlock: block
      };
    }

    // 3. Message Authorization
    this.circuitBreaker.commitMessage(channelId, senderPid);
    const block = this.auditLedger.seal('IPC_MESSAGE_AUTHORIZED', {
      channelId,
      senderPid,
      entropy: scan.entropy,
      sizeBytes: scan.sizeBytes
    });

    return {
      authorized: true,
      status: 'MESSAGE_DELIVERED',
      channelId,
      senderPid,
      entropy: scan.entropy,
      circuitState: this.circuitBreaker.state,
      auditBlock: block
    };
  }

  getMetrics() {
    return {
      circuitState: this.circuitBreaker.state,
      isolatedChannelsCount: this.circuitBreaker.isolatedChannels.size,
      totalAuditBlocks: this.auditLedger.chain.length,
      chainIntegrity: this.auditLedger.verifyChain().valid
    };
  }
}

module.exports = { QNXSentinel };
