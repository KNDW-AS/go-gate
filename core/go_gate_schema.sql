-- go_gate_schema.sql
-- GO-GATE: Two-Phase Commit with Risk-Based Autonomous Approval

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Policy definitions with dynamic thresholds
CREATE TABLE IF NOT EXISTS go_policies (
    policy_id INTEGER PRIMARY KEY,
    op_type TEXT NOT NULL UNIQUE CHECK(op_type IN ('FILE_WRITE', 'FILE_DELETE', 'SHELL_EXEC', 'GIT_COMMIT', 'GIT_PUSH', 'SUDO_EXEC')),
    default_risk TEXT NOT NULL CHECK(default_risk IN ('LOW', 'MEDIUM', 'HIGH')),
    verification_threshold REAL NOT NULL DEFAULT 0.8 CHECK(verification_threshold >= 0.0 AND verification_threshold <= 1.0),
    auto_approve_allowed BOOLEAN NOT NULL DEFAULT 0,
    requires_cross_agent BOOLEAN NOT NULL DEFAULT 0,
    verifier_agent TEXT,
    human_escalation_pattern TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Main transactions table
CREATE TABLE IF NOT EXISTS go_transactions (
    tx_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('PREPARING', 'PENDING_AUTO_APPROVAL', 'PENDING_HUMAN_APPROVAL', 'AUTO_APPROVED', 'COMMITTING', 'COMMITTED', 'ABORTED')),
    risk_level TEXT NOT NULL CHECK(risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    policy_engine TEXT NOT NULL DEFAULT 'standard',
    policy_snapshot_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    approved_at DATETIME,
    completed_at DATETIME,  -- P5: When transaction finished (COMMITTED/ABORTED)
    approved_by TEXT,
    approval_type TEXT CHECK(approval_type IN ('HUMAN', 'AUTO_AGENT', 'CROSS_AGENT')),
    evidence_hash TEXT,
    rollback_script TEXT,
    commit_attempts INTEGER NOT NULL DEFAULT 0,
    error_log TEXT,
    verifier_agent TEXT,
    proposer TEXT NOT NULL DEFAULT 'system'
);

-- Individual operations within transactions
CREATE TABLE IF NOT EXISTS go_operations (
    op_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id TEXT NOT NULL REFERENCES go_transactions(tx_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    op_type TEXT NOT NULL,  -- Allow unknown types for fail-closed behavior
    target_path TEXT NOT NULL,
    payload TEXT NOT NULL,
    pre_check_sql TEXT,
    post_check_sql TEXT,
    undo_payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'EXECUTED', 'ROLLED_BACK', 'FAILED')),
    UNIQUE(tx_id, sequence)
);

-- Resource locks for concurrency control
CREATE TABLE IF NOT EXISTS go_locks (
    lock_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id TEXT NOT NULL REFERENCES go_transactions(tx_id) ON DELETE CASCADE,
    resource_id TEXT NOT NULL,
    lock_mode TEXT NOT NULL CHECK(lock_mode IN ('READ', 'WRITE', 'SHARED', 'EXCLUSIVE')),
    lock_status TEXT NOT NULL CHECK(lock_status IN ('GRANTED', 'WAITING')),
    acquired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    granted_at DATETIME,
    expires_at DATETIME NOT NULL,
    waiting_for_tx_id TEXT REFERENCES go_transactions(tx_id),
    UNIQUE(resource_id, tx_id)
);

-- Audit trail (immutable)
CREATE TABLE IF NOT EXISTS go_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    details TEXT,
    actor TEXT NOT NULL DEFAULT 'system'
);

-- Invariant checks
CREATE TABLE IF NOT EXISTS go_invariants (
    check_name TEXT PRIMARY KEY,
    check_sql TEXT NOT NULL,
    last_verified DATETIME,
    last_result BOOLEAN,
    violation_count INTEGER NOT NULL DEFAULT 0
);

-- Insert default policies
INSERT OR REPLACE INTO go_policies (op_type, default_risk, verification_threshold, auto_approve_allowed, requires_cross_agent, verifier_agent) VALUES
('FILE_WRITE', 'LOW', 0.70, 1, 0, NULL),
('FILE_DELETE', 'MEDIUM', 0.90, 1, 1, 'zeph'),
('GIT_COMMIT', 'MEDIUM', 0.85, 1, 1, 'aeris_core'),
('GIT_PUSH', 'HIGH', 1.00, 0, 0, NULL),
('SHELL_EXEC', 'HIGH', 1.00, 0, 0, NULL),
('SUDO_EXEC', 'HIGH', 1.00, 0, 0, NULL);

-- Insert invariant checks
INSERT OR REPLACE INTO go_invariants (check_name, check_sql) VALUES 
('no_orphan_committing', 'SELECT CASE WHEN COUNT(*) = 0 THEN 1 ELSE 0 END FROM go_transactions WHERE status = ''COMMITTING'' AND datetime(created_at) < datetime(''now'', ''-5 minutes'')'),
('no_expired_locks', 'SELECT CASE WHEN COUNT(*) = 0 THEN 1 ELSE 0 END FROM go_locks WHERE expires_at < datetime(''now'')');

CREATE INDEX IF NOT EXISTS idx_transactions_status ON go_transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_created ON go_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_operations_tx_id ON go_operations(tx_id);
CREATE INDEX IF NOT EXISTS idx_locks_tx_id ON go_locks(tx_id);
CREATE INDEX IF NOT EXISTS idx_locks_resource ON go_locks(resource_id);
CREATE INDEX IF NOT EXISTS idx_locks_status ON go_locks(lock_status);
CREATE INDEX IF NOT EXISTS idx_audit_tx_id ON go_audit(tx_id);
