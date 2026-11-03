/**
 * QNXGuard — Microkernel Cryptographic Flight Recorder (SHA-256)
 * 
 * Cryptographically seals IPC message headers, circuit trip events,
 * and thread state transitions into an immutable parent-hashed ledger.
 */

const crypto = require('node:crypto');

class AuditLedger {
  constructor() {
    this.chain = [];
    this._initGenesis();
  }

  _initGenesis() {
    const payload = {
      event: 'QNX_NEUTRINO_RTOS_GENESIS',
      kernelVersion: 'QNX Neutrino 8.0.0 (x86_64 / AArch64)',
      systemMode: 'FAIL_CLOSED_HARD_REAL_TIME',
      timestamp: 1762128000000
    };
    const hash = this._hash(0, 1762128000000, payload, '0'.repeat(64));
    this.chain.push({
      index: 0,
      timestamp: 1762128000000,
      payload,
      prevHash: '0'.repeat(64),
      hash
    });
  }

  _hash(index, timestamp, payload, prevHash) {
    const data = `${index}|${timestamp}|${JSON.stringify(payload)}|${prevHash}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  seal(eventType, eventData) {
    const prev = this.chain[this.chain.length - 1];
    const index = this.chain.length;
    const timestamp = Date.now();
    const payload = { eventType, ...eventData };
    const hash = this._hash(index, timestamp, payload, prev.hash);

    const block = { index, timestamp, payload, prevHash: prev.hash, hash };
    this.chain.push(block);
    return block;
  }

  verifyChain() {
    for (let i = 1; i < this.chain.length; i++) {
      const cur = this.chain[i];
      const prev = this.chain[i - 1];

      if (cur.prevHash !== prev.hash) {
        return { valid: false, error: `Broken link at block #${i}` };
      }

      const recomputed = this._hash(cur.index, cur.timestamp, cur.payload, cur.prevHash);
      if (cur.hash !== recomputed) {
        return { valid: false, error: `Tampered payload at block #${i}` };
      }
    }
    return { valid: true, blockCount: this.chain.length };
  }
}

module.exports = { AuditLedger };
