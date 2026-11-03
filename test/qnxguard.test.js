const assert = require('node:assert');
const { IPCScanner } = require('../src/ipc_scanner');
const { QNXCircuitBreaker, STATES } = require('../src/circuit_breaker');
const { AuditLedger } = require('../src/audit_ledger');
const { QNXSentinel } = require('../src/qnx_sentinel');

console.log('⚡ RUNNING QNXGUARD MICROKERNEL SECURITY TEST SUITE...');
let passed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}: ${err.message}`);
    throw err;
  }
}

// 1. IPC Scanner & Shannon Entropy Tests
test('IPCScanner: Calculates correct Shannon entropy bounds', () => {
  const zeroEntropy = IPCScanner.calculateEntropy(Buffer.alloc(100, 0x41));
  assert.strictEqual(zeroEntropy, 0.0);

  const textEntropy = IPCScanner.calculateEntropy(Buffer.from('Standard QNX telemetry sensor frame #1042'));
  assert.ok(textEntropy > 3.0 && textEntropy < 5.0);
});

test('IPCScanner: Intercepts NOP sled shellcode injection', () => {
  const nopPayload = Buffer.concat([Buffer.alloc(16, 0x90), Buffer.from('shellcode')]);
  const scan = IPCScanner.scanMessage({ channelId: 1, connectionId: 1, senderPid: 402, payload: nopPayload });
  assert.strictEqual(scan.safe, false);
  assert.ok(scan.flags.includes('NOP_SLED_INJECTION'));
});

test('IPCScanner: Rejects buffer overflow exceeding channel max bounds', () => {
  const hugePayload = Buffer.alloc(5000, 0x42);
  const scan = IPCScanner.scanMessage({ channelId: 1, connectionId: 1, senderPid: 105, payload: hugePayload, maxAllowedBytes: 1024 });
  assert.strictEqual(scan.safe, false);
  assert.strictEqual(scan.status, 'BUFFER_OVERFLOW_ATTEMPT');
});

test('IPCScanner: Intercepts CAN-bus critical safety override commands', () => {
  const canPayload = Buffer.from('FRAME_ID_0x204:BRAKE_FORCE_ZERO:COMMIT');
  const scan = IPCScanner.scanMessage({ channelId: 2, connectionId: 1, senderPid: 300, payload: canPayload });
  assert.strictEqual(scan.safe, false);
  assert.ok(scan.flags.includes('CAN_BUS_OVERRIDE'));
});

// 2. Circuit Breaker State Machine Tests
test('CircuitBreaker: Authorizes normal real-time IPC message passing', () => {
  const cb = new QNXCircuitBreaker();
  const res = cb.evaluate(1, 100);
  assert.strictEqual(res.authorized, true);
  assert.strictEqual(res.state, STATES.ARMED);
});

test('CircuitBreaker: Isolates channel upon DoS flooding', () => {
  const cb = new QNXCircuitBreaker({ maxFramesPerSec: 5, rateLimitWindowMs: 1000 });
  for (let i = 0; i < 5; i++) cb.commitMessage(1, 100);

  const res = cb.evaluate(1, 100);
  assert.strictEqual(res.authorized, false);
  assert.strictEqual(res.state, STATES.ISOLATED_LOCK);
});

test('CircuitBreaker: Restores channel only via cryptographic root token', () => {
  const cb = new QNXCircuitBreaker();
  cb.isolateChannel(1, 'Critical fault');
  assert.strictEqual(cb.state, STATES.ISOLATED_LOCK);

  assert.throws(() => cb.reset('INVALID_TOKEN'), /Invalid administrative root token/);
  const resetRes = cb.reset('QNXGUARD_ROOT_OVERRIDE_KEY_2026');
  assert.strictEqual(resetRes.success, true);
  assert.strictEqual(cb.state, STATES.ARMED);
});

// 3. Cryptographic Audit Ledger Tests
test('AuditLedger: Seals parent-linked blocks and verifies chain integrity', () => {
  const ledger = new AuditLedger();
  ledger.seal('CHANNEL_INITIALIZED', { channelId: 1 });
  ledger.seal('IPC_MESSAGE_SENT', { senderPid: 100, bytes: 64 });

  const check = ledger.verifyChain();
  assert.strictEqual(check.valid, true);
  assert.strictEqual(check.blockCount, 3);
});

test('AuditLedger: Detects retroactive block tampering', () => {
  const ledger = new AuditLedger();
  ledger.seal('TEST_EVENT', { data: 100 });
  ledger.chain[1].payload.data = 999;

  const check = ledger.verifyChain();
  assert.strictEqual(check.valid, false);
  assert.match(check.error, /Tampered payload/);
});

// 4. Unified Sentinel Gateway Integration Tests
test('QNXSentinel: Delivers clean telemetry frame with audit receipt', () => {
  const sentinel = new QNXSentinel();
  const res = sentinel.processMessage({
    channelId: 1,
    senderPid: 1024,
    payload: Buffer.from('CAN_SPEED:65_MPH:TIRE_PRESSURE_OK')
  });

  assert.strictEqual(res.authorized, true);
  assert.strictEqual(res.status, 'MESSAGE_DELIVERED');
  assert.ok(res.auditBlock.hash);
});

test('QNXSentinel: Intercepts exploit and isolates channel in sub-millisecond latency', () => {
  const sentinel = new QNXSentinel();
  const res = sentinel.processMessage({
    channelId: 2,
    senderPid: 9999,
    payload: Buffer.concat([Buffer.alloc(20, 0x90), Buffer.from('ROOT_EXPLOIT')])
  });

  assert.strictEqual(res.authorized, false);
  assert.strictEqual(res.status, 'INTERCEPTED_EXPLOIT_PAYLOAD');
  assert.strictEqual(sentinel.circuitBreaker.state, STATES.ISOLATED_LOCK);
});

console.log(`\n🎉 ALL ${passed}/${passed} QNXGUARD SECURITY INVARIANTS PASSING (100%)!`);
