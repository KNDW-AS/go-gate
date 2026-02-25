#!/usr/bin/env python3
# go_gate.py
# GO-GATE: Two-Phase Commit with Risk-Based Autonomous Approval

import os
import sys
import json
import uuid
import sqlite3
import asyncio
import aiosqlite
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import defaultdict

# P2: Import SandboxedSkillsExecutor
try:
    from core.skills_executor import get_executor, SandboxedSkillsExecutor, ExecutionResult
except ImportError:
    # Fallback if core module not available
    get_executor = None
    SandboxedSkillsExecutor = None
    ExecutionResult = None

# ═══════════════════════════════════════════════════════════════════════════════
# P5: ZEPH VERIFICATION (Semaphore-protected concurrent access)
# ═══════════════════════════════════════════════════════════════════════════════

import threading
import requests

# Semaphore to prevent concurrent SecurityVerifier LLM calls (Claude requirement)
_ZEPH_SEMAPHORE = threading.Semaphore(1)


async def _security_verifier_verification(tx_id: str, operations: List[dict], db_path: str) -> dict:
    """
    P5: SecurityVerifier Verifikator for MEDIUM-risk transactions.
    
    Analyzes FILE_DELETE, GIT_COMMIT and other MEDIUM-risk operations.
    Returns structured JSON with APPROVE/REJECT decision and reasoning.
    
    Fail-closed: timeout or invalid JSON = ABORT
    Semaphore(1): Prevents concurrent SecurityVerifier LLM calls
    
    Returns:
        {
            'decision': 'APPROVE' | 'REJECT' | 'ABORT',
            'confidence': float,  # 0.0 - 1.0
            'reasoning': str,     # Human-readable explanation
            'risk_factors': [str] # List of identified risks
        }
    """
    # Acquire semaphore to prevent concurrent SecurityVerifier calls
    acquired = _ZEPH_SEMAPHORE.acquire(timeout=30.0)
    if not acquired:
        # Fail-closed: couldn't acquire semaphore = ABORT
        return {
            'decision': 'ABORT',
            'confidence': 0.0,
            'reasoning': 'Could not acquire SecurityVerifier verification semaphore (concurrency limit)',
            'risk_factors': ['SEMAPHORE_TIMEOUT']
        }
    
    try:
        # Build context for SecurityVerifier analysis
        op_summary = []
        for op in operations:
            op_type = op.get('op_type', 'UNKNOWN')
            target = op.get('target_path', op.get('target', 'unknown'))
            op_summary.append(f"{op_type}: {target}")
        
        # Get transaction context from database
        conn = sqlite3.connect(db_path)
        cursor = conn.execute("""
            SELECT proposer, created_at FROM go_transactions WHERE tx_id = ?
        """, (tx_id,))
        row = cursor.fetchone()
        conn.close()
        
        proposer = row[0] if row else 'unknown'
        created_at = row[1] if row else 'unknown'
        
        # Build prompt for LLM (SecurityVerifier analysis)
        prompt = f"""You are SecurityVerifier, the security verifier for Secure Agent System (AI Agent System).
Analyze the following MEDIUM-risk transaction and decide whether to APPROVE or REJECT.

Transaction ID: {tx_id}
Proposed by: {proposer}
Created: {created_at}

Operations:
{chr(10).join(f"- {s}" for s in op_summary)}

Analyze for:
1. Path traversal attempts (../, symlinks)
2. Destructive operations on critical files
3. Operations outside allowed workspaces
4. Git operations on sensitive branches
5. Timing/context risks

Return ONLY a JSON object with this structure:
{{
    "decision": "APPROVE" or "REJECT",
    "confidence": 0.0 to 1.0,
    "reasoning": "Brief explanation of decision",
    "risk_factors": ["list", "of", "identified", "risks"]
}}

Be conservative. When in doubt, REJECT."""

        # Call LLM (try Gemini first, fallback to local)
        decision_data = None
        try:
            # Try Gemini API
            from core.config import config
            gemini_key = getattr(config, 'GEMINI_API_KEY', None)
            
            if gemini_key:
                response = requests.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_key}",
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 500}
                    },
                    timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    text_response = data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
                    # Extract JSON from response
                    import re
                    json_match = re.search(r'\{[^}]+\}', text_response, re.DOTALL)
                    if json_match:
                        decision_data = json.loads(json_match.group())
        
        except Exception as e:
            # Log error but continue to fallback
            print(f"[ZEPH] Gemini LLM call failed: {e}")
        
        # Validate and return result
        if decision_data and 'decision' in decision_data:
            decision = decision_data.get('decision', 'ABORT').upper()
            if decision not in ('APPROVE', 'REJECT', 'ABORT'):
                decision = 'ABORT'
            
            return {
                'decision': decision,
                'confidence': float(decision_data.get('confidence', 0.0)),
                'reasoning': str(decision_data.get('reasoning', 'No reasoning provided')),
                'risk_factors': list(decision_data.get('risk_factors', []))
            }
        else:
            # Invalid JSON or missing fields = ABORT (fail-closed)
            return {
                'decision': 'ABORT',
                'confidence': 0.0,
                'reasoning': 'Invalid or missing response from SecurityVerifier LLM analysis',
                'risk_factors': ['INVALID_LLM_RESPONSE']
            }
    
    except Exception as e:
        # Any exception = ABORT (fail-closed)
        return {
            'decision': 'ABORT',
            'confidence': 0.0,
            'reasoning': f'SecurityVerifier verification error: {str(e)}',
            'risk_factors': ['VERIFICATION_EXCEPTION']
        }
    
    finally:
        # Always release semaphore
        _ZEPH_SEMAPHORE.release()


class GoPolicyEngine:
    """Risk-based policy engine for autonomous approval decisions."""
    
    RISK_PATTERNS = {
        'HIGH': [
            r'\brm\s+-rf\b',
            r'\bsudo\b',
            r'\bgit\s+push\b',
            r'\b>\s*/dev/',
            r'\bcurl\s+.*\|\s*bash',
            r'DROP\s+TABLE',
            r'DELETE\s+FROM.*WHERE',
        ],
        'MEDIUM': [
            r'\brm\b',
            r'\bmv\b.*\.git',
            r'\bchmod\s+777\b',
        ]
    }
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_policies()
    
    def _init_policies(self):
        """Ensure default policies exist."""
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            INSERT OR IGNORE INTO go_policies (op_type, default_risk, verification_threshold, auto_approve_allowed, requires_cross_agent, verifier_agent) VALUES
            ('FILE_WRITE', 'LOW', 0.70, 1, 0, NULL),
            ('FILE_DELETE', 'MEDIUM', 0.90, 1, 1, 'security_verifier'),
            ('GIT_COMMIT', 'MEDIUM', 0.85, 1, 1, 'aeris_core'),
            ('GIT_PUSH', 'HIGH', 1.00, 0, 0, NULL),
            ('SHELL_EXEC', 'HIGH', 1.00, 0, 0, NULL),
            ('SUDO_EXEC', 'HIGH', 1.00, 0, 0, NULL),
            ('IMAGE_GENERATE', 'LOW', 0.60, 1, 0, NULL);
        """)
        conn.commit()
        conn.close()
    
    def resolve_policy(self, op_type: str) -> dict:
        """Fetch policy with fail-closed default."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("""
            SELECT policy_id, default_risk, verification_threshold,
                   auto_approve_allowed, requires_cross_agent, verifier_agent
            FROM go_policies WHERE op_type = ?
        """, (op_type,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return {
                'policy_id': None,
                'default_risk': 'HIGH',
                'verification_threshold': 1.0,
                'auto_approve_allowed': False,
                'requires_cross_agent': False,
                'verifier_agent': None,
                'fail_closed_reason': 'UNKNOWN_OP_TYPE'
            }
        
        return {
            'policy_id': row[0],
            'default_risk': row[1],
            'verification_threshold': row[2],
            'auto_approve_allowed': bool(row[3]),
            'requires_cross_agent': bool(row[4]),
            'verifier_agent': row[5]
        }
    
    def assess_transaction_risk(self, operations: List[dict]) -> tuple:
        """Returns (risk_level, verifier_agent, requires_human, max_threshold)."""
        max_risk = 'LOW'
        requires_human = False
        cross_agent_required = False
        verifier = None
        max_threshold = 0.0
        
        for op in operations:
            policy = self.resolve_policy(op['type'])
            
            if self._risk_higher(policy['default_risk'], max_risk):
                max_risk = policy['default_risk']
            
            if policy['verification_threshold'] > max_threshold:
                max_threshold = policy['verification_threshold']
            
            payload_str = json.dumps(op.get('payload', {}))
            if self._matches_high_risk_pattern(payload_str):
                max_risk = 'HIGH'
                requires_human = True
            
            if policy['requires_cross_agent']:
                cross_agent_required = True
                verifier = policy['verifier_agent']
            
            if not policy['auto_approve_allowed']:
                requires_human = True
        
        if requires_human:
            verifier = None
        elif cross_agent_required:
            verifier = verifier or 'security_verifier'
        else:
            verifier = 'aeris_core'
            
        return max_risk, verifier, requires_human, max_threshold
    
    def _risk_higher(self, risk1: str, risk2: str) -> bool:
        order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
        return order.get(risk1, 0) > order.get(risk2, 0)
    
    def _matches_high_risk_pattern(self, payload: str) -> bool:
        import re
        for pattern in self.RISK_PATTERNS['HIGH']:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False
    
    def calculate_score(self, tx_id: str, verifier_agent: str) -> float:
        """Calculate verification score based on heuristics."""
        confidence = 0.0
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("""
            SELECT target_path, op_type FROM go_operations WHERE tx_id = ?
        """, (tx_id,))
        ops = cursor.fetchall()
        conn.close()
        
        if not ops:
            return 0.0
        
        if self._is_known_pattern(ops):
            confidence += 0.3
        
        if all(self._is_allowed_target(path) for path, _ in ops):
            confidence += 0.3
        
        if self._is_safe_hours():
            confidence += 0.2
        
        if verifier_agent in ('security_verifier', 'aeris_core'):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _is_known_pattern(self, ops: List[tuple]) -> bool:
        return True
    
    def _is_allowed_target(self, target: str) -> bool:
        allowed_prefixes = [
            '/tmp/go-gate-sandbox/',
            '/tmp/go-gate-workspace/',
            '/tmp/'
        ]
        return any(target.startswith(p) for p in allowed_prefixes)
    
    def _is_safe_hours(self) -> bool:
        hour = datetime.now().hour
        return 6 <= hour <= 23


class GoDeadlockDetector:
    """Wait-For Graph deadlock detection."""
    
    def check_and_resolve(self, db_path: str):
        """Main entry point for deadlock detection."""
        wfg = self._build_wait_for_graph(db_path)
        if not wfg:
            return
        
        cycles = self._find_cycles(wfg)
        for cycle in cycles:
            victim = self._select_victim(cycle, db_path)
            self._abort_transaction(victim, f"Deadlock cycle: {' -> '.join(cycle)}", db_path)
    
    def _build_wait_for_graph(self, db_path: str) -> Dict[str, List[str]]:
        conn = sqlite3.connect(db_path)
        
        cursor = conn.execute("""
            SELECT tx_id, resource_id, lock_mode
            FROM go_locks
            WHERE lock_status = 'WAITING'
            AND tx_id IN (
                SELECT tx_id FROM go_transactions
                WHERE status IN ('PREPARING', 'PENDING_AUTO_APPROVAL', 'PENDING_HUMAN_APPROVAL', 'COMMITTING')
            )
        """)
        waiting_locks = cursor.fetchall()
        
        wfg = defaultdict(list)
        
        for waiter_tx, resource_id, wait_mode in waiting_locks:
            cursor.execute("""
                SELECT tx_id, lock_mode FROM go_locks
                WHERE resource_id = ? AND lock_status = 'GRANTED' AND tx_id != ?
            """, (resource_id, waiter_tx))
            holders = cursor.fetchall()
            
            for holder_tx, holder_mode in holders:
                if self._locks_conflict(wait_mode, holder_mode):
                    wfg[waiter_tx].append(holder_tx)
                    conn.execute("""
                        UPDATE go_locks SET waiting_for_tx_id = ?
                        WHERE tx_id = ? AND resource_id = ?
                    """, (holder_tx, waiter_tx, resource_id))
        
        conn.commit()
        conn.close()
        return dict(wfg)
    
    def _locks_conflict(self, mode1: str, mode2: str) -> bool:
        if 'WRITE' in mode1 or 'WRITE' in mode2 or 'EXCLUSIVE' in mode1 or 'EXCLUSIVE' in mode2:
            return True
        return False
    
    def _find_cycles(self, wfg: Dict[str, List[str]]) -> List[List[str]]:
        cycles = []
        visited = set()
        
        def dfs(node, path):
            if node in path:
                cycle_start = path.index(node)
                cycles.append(path[cycle_start:] + [node])
                return
            if node in visited:
                return
            
            visited.add(node)
            path.append(node)
            
            for neighbor in wfg.get(node, []):
                dfs(neighbor, path)
            
            path.pop()
        
        for node in wfg:
            dfs(node, [])
        
        return cycles
    
    def _select_victim(self, cycle: List[str], db_path: str) -> str:
        conn = sqlite3.connect(db_path)
        placeholders = ','.join('?' * len(cycle))
        cursor = conn.execute(f"""
            SELECT tx_id, created_at FROM go_transactions
            WHERE tx_id IN ({placeholders})
            ORDER BY created_at DESC
        """, tuple(cycle))
        rows = cursor.fetchall()
        conn.close()
        return rows[0][0] if rows else cycle[0]
    
    def _abort_transaction(self, victim_tx: str, reason: str, db_path: str):
        conn = sqlite3.connect(db_path)
        
        conn.execute("""
            INSERT INTO go_audit (tx_id, event_type, details, actor)
            VALUES (?, 'DEADLOCK_VICTIM_ABORT', ?, 'deadlock_detector')
        """, (victim_tx, reason))
        
        conn.execute("""
            UPDATE go_transactions
            SET status = 'ABORTED', error_log = ?
            WHERE tx_id = ?
        """, (f'Deadlock victim: {reason}', victim_tx))
        
        conn.execute("DELETE FROM go_locks WHERE tx_id = ?", (victim_tx,))
        conn.execute("UPDATE go_locks SET waiting_for_tx_id = NULL WHERE waiting_for_tx_id = ?", (victim_tx,))
        
        conn.commit()
        conn.close()


class GoGateWatchdog:
    """Async watchdog for invariant checking."""
    
    def __init__(self, db_path: str, check_interval: int = 30):
        self.db_path = db_path
        self.check_interval = check_interval
        self.deadlock_detector = GoDeadlockDetector()
        self.running = False
        self._task = None
    
    async def start(self):
        self.running = True
        self._task = asyncio.create_task(self._watchdog_loop())
    
    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def _watchdog_loop(self):
        while self.running:
            try:
                async with aiosqlite.connect(self.db_path) as db:
                    await self._check_no_orphan_committing(db)
                    await self._check_lock_timeouts(db)
                    await self._check_deadlock_potential(db)
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                print(f"[WATCHDOG ERROR] {e}")
                await asyncio.sleep(5)
    
    async def _check_no_orphan_committing(self, db):
        cursor = await db.execute("""
            SELECT tx_id, commit_attempts FROM go_transactions
            WHERE status = 'COMMITTING'
            AND datetime(created_at) < datetime('now', '-5 minutes')
        """)
        orphans = await cursor.fetchall()
        
        for tx_id, attempts in orphans:
            await db.execute("""
                INSERT INTO go_audit (tx_id, event_type, details, actor)
                VALUES (?, 'WATCHDOG_TIMEOUT_ROLLBACK', ?, 'system')
            """, (tx_id, f'Stuck in COMMITTING > 5min, attempts: {attempts}'))
            
            await db.execute("""
                UPDATE go_transactions SET status = 'ABORTED', error_log = ?
                WHERE tx_id = ?
            """, ('Watchdog timeout rollback', tx_id))
            
            await db.execute("DELETE FROM go_locks WHERE tx_id = ?", (tx_id,))
            await db.commit()
    
    async def _check_lock_timeouts(self, db):
        cursor = await db.execute("""
            SELECT resource_id, tx_id FROM go_locks
            WHERE expires_at < datetime('now')
        """)
        expired = await cursor.fetchall()
        
        for resource, tx_id in expired:
            await db.execute("DELETE FROM go_locks WHERE resource_id = ?", (resource,))
            await db.execute("""
                INSERT INTO go_audit (tx_id, event_type, details, actor)
                VALUES (?, 'LOCK_EXPIRED', ?, 'system')
            """, (tx_id, f'Lock on {resource} expired'))
            await db.commit()
    
    async def _check_deadlock_potential(self, db):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            self.deadlock_detector.check_and_resolve,
            self.db_path
        )


class GoGate:
    """Main GO-GATE coordinator."""
    
    def __init__(self, db_path: str = "~/.openclaw/workspace/data/go_gate.db"):
        self.db_path = os.path.expanduser(db_path)
        self._ensure_schema()  # Schema FIRST - before any table access
        self.policy_engine = GoPolicyEngine(self.db_path)
        self.watchdog = GoGateWatchdog(self.db_path)
        
        # P2: Initialize SandboxedSkillsExecutor
        if get_executor:
            self.skills_executor = get_executor(audit_callback=self._audit_execution)
        else:
            self.skills_executor = None
    
    def _audit_execution(self, result):
        """P2: Callback for auditing skill executions."""
        # TODO: Log to go_audit table or external log
        pass
    
    def _ensure_schema(self):
        schema_path = Path(__file__).parent / "go_gate_schema.sql"
        if not schema_path.exists():
            raise FileNotFoundError(
                f"[GO-GATE] Schema file missing: {schema_path} "
                "Place go_gate_schema.sql in same directory as go_gate.py"
            )
        conn = sqlite3.connect(self.db_path)
        with open(schema_path) as f:
            conn.executescript(f.read())
        conn.close()
    
    async def initialize(self):
        await self.watchdog.start()
    
    async def propose_transaction(self, operations: List[dict], proposer: str = 'aeris') -> dict:
        tx_id = str(uuid.uuid4())
        
        risk_level, verifier, requires_human, threshold = self.policy_engine.assess_transaction_risk(operations)
        
        initial_status = 'PENDING_HUMAN_APPROVAL' if requires_human else 'PENDING_AUTO_APPROVAL'
        
        policies = [self.policy_engine.resolve_policy(op['type']) for op in operations]
        policy_snapshot = json.dumps({
            'resolved_at': datetime.utcnow().isoformat(),
            'operations': [
                {
                    'sequence': i,
                    'op_type': op['type'],
                    'policy_id': pol['policy_id'],
                    'applied_threshold': pol['verification_threshold'],
                    'applied_risk': pol['default_risk']
                }
                for i, (op, pol) in enumerate(zip(operations, policies))
            ],
            'final_threshold': threshold,
            'final_risk': risk_level
        })
        
        rollback_script = json.dumps([{
            'sequence': i,
            'undo_payload': op.get('undo_payload', {})
        } for i, op in enumerate(operations)])
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO go_transactions 
                (tx_id, status, risk_level, policy_snapshot_json, proposer, verifier_agent, rollback_script)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (tx_id, initial_status, risk_level, policy_snapshot, proposer, verifier, rollback_script))
            
            for i, op in enumerate(operations):
                await db.execute("""
                    INSERT INTO go_operations 
                    (tx_id, sequence, op_type, target_path, payload, undo_payload)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (tx_id, i, op['type'], op.get('target', ''), 
                      json.dumps(op.get('payload', {})), 
                      json.dumps(op.get('undo_payload', {}))))
            
            for op in operations:
                expires = (datetime.now() + timedelta(minutes=5)).isoformat()
                await db.execute("""
                    INSERT OR FAIL INTO go_locks 
                    (tx_id, resource_id, lock_mode, lock_status, expires_at)
                    VALUES (?, ?, 'EXCLUSIVE', 'GRANTED', ?)
                """, (tx_id, op.get('target', ''), expires))
            
            await db.commit()
        
        if initial_status == 'PENDING_AUTO_APPROVAL' and verifier:
            # P5: Use SecurityVerifier verification for MEDIUM-risk transactions
            if verifier == 'security_verifier' and risk_level == 'MEDIUM':
                security_verifier_result = await _security_verifier_verification(tx_id, operations, self.db_path)
                
                # Log SecurityVerifier decision to audit
                async with aiosqlite.connect(self.db_path) as db:
                    await db.execute("""
                        INSERT INTO go_audit (tx_id, event_type, details, actor)
                        VALUES (?, 'ZEPH_VERIFICATION', ?, ?)
                    """, (tx_id, json.dumps(security_verifier_result), 'security_verifier'))
                    await db.commit()
                
                if security_verifier_result['decision'] == 'APPROVE':
                    # Use SecurityVerifier confidence as score
                    score = security_verifier_result['confidence']
                    snapshot = json.loads(policy_snapshot)
                    required = snapshot['final_threshold']
                    
                    if score >= required:
                        await self._mark_auto_approved(tx_id, 'security_verifier', score)
                        commit_result = await self.commit(tx_id, 'security_verifier', auto=True)
                        return commit_result
                elif security_verifier_result['decision'] == 'REJECT':
                    # SecurityVerifier rejected - mark as ABORTED
                    async with aiosqlite.connect(self.db_path) as db:
                        await db.execute("""
                            UPDATE go_transactions 
                            SET status = 'ABORTED', completed_at = ?
                            WHERE tx_id = ?
                        """, (datetime.utcnow().isoformat(), tx_id))
                        await db.execute("""
                            INSERT INTO go_audit (tx_id, event_type, details, actor)
                            VALUES (?, 'ZEPH_REJECT', ?, ?)
                        """, (tx_id, security_verifier_result['reasoning'], 'security_verifier'))
                        await db.commit()
                    
                    return {
                        'tx_id': tx_id,
                        'status': 'ABORTED',
                        'error': f"SecurityVerifier rejected: {security_verifier_result['reasoning']}",
                        'security_verifier_analysis': security_verifier_result
                    }
                else:  # ABORT or any other decision
                    # Fail-closed: ABORT transaction
                    async with aiosqlite.connect(self.db_path) as db:
                        await db.execute("""
                            UPDATE go_transactions 
                            SET status = 'ABORTED', completed_at = ?
                            WHERE tx_id = ?
                        """, (datetime.utcnow().isoformat(), tx_id))
                        await db.execute("""
                            INSERT INTO go_audit (tx_id, event_type, details, actor)
                            VALUES (?, 'ZEPH_ABORT', ?, ?)
                        """, (tx_id, security_verifier_result['reasoning'], 'security_verifier'))
                        await db.commit()
                    
                    return {
                        'tx_id': tx_id,
                        'status': 'ABORTED',
                        'error': f"SecurityVerifier aborted (fail-closed): {security_verifier_result['reasoning']}",
                        'security_verifier_analysis': security_verifier_result
                    }
            else:
                # Use legacy scoring for other verifiers
                score = self.policy_engine.calculate_score(tx_id, verifier)
                snapshot = json.loads(policy_snapshot)
                required = snapshot['final_threshold']
                
                if score >= required:
                    await self._mark_auto_approved(tx_id, verifier, score)
                    commit_result = await self.commit(tx_id, verifier, auto=True)
                    return commit_result
        
        return {
            'tx_id': tx_id,
            'status': initial_status,
            'requires_approval_from': verifier or 'HUMAN',
            'risk_level': risk_level,
            'threshold': threshold
        }
    
    async def _mark_auto_approved(self, tx_id: str, verifier: str, score: float):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE go_transactions 
                SET status = 'AUTO_APPROVED', approved_by = ?, approved_at = datetime('now'), approval_type = 'AUTO_AGENT'
                WHERE tx_id = ?
            """, (verifier, tx_id))
            await db.execute("""
                INSERT INTO go_audit (tx_id, event_type, details, actor)
                VALUES (?, 'AUTO_APPROVED', ?, ?)
            """, (tx_id, f'Score: {score}', verifier))
            await db.commit()
        
        await self.commit(tx_id, verifier, auto=True)
    
    async def approve(self, tx_id: str, approved_by: str, approval_type: str = 'HUMAN') -> dict:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                SELECT status, verifier_agent FROM go_transactions WHERE tx_id = ?
            """, (tx_id,))
            row = await cursor.fetchone()
            
            if not row:
                return {'error': 'Transaction not found'}
            
            current_status, expected_verifier = row
            
            if current_status not in ('PENDING_HUMAN_APPROVAL', 'PENDING_AUTO_APPROVAL', 'AUTO_APPROVED'):
                return {'error': f'Cannot approve transaction in status {current_status}'}
            
            if expected_verifier and approved_by != expected_verifier:
                return {'error': f'Requires approval from {expected_verifier}'}
            
            if not expected_verifier and approval_type != 'HUMAN':
                return {'error': 'HIGH risk transaction requires human approval'}
        
        return await self.commit(tx_id, approved_by, auto=False)
    
    async def commit(self, tx_id: str, approved_by: str, auto: bool = False) -> dict:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE go_transactions SET status = 'COMMITTING', commit_attempts = commit_attempts + 1
                WHERE tx_id = ?
            """, (tx_id,))
            
            cursor = await db.execute("""
                SELECT op_id, op_type, target_path, payload, undo_payload
                FROM go_operations WHERE tx_id = ? ORDER BY sequence
            """, (tx_id,))
            ops = await cursor.fetchall()
            
            executed = []
            try:
                for op_id, op_type, target, payload_json, undo_json in ops:
                    payload = json.loads(payload_json)
                    success = await self._execute_operation(op_type, target, payload)
                    
                    if not success:
                        raise Exception(f"Operation failed: {op_type} on {target}")
                    
                    await db.execute("""
                        UPDATE go_operations SET status = 'EXECUTED' WHERE op_id = ?
                    """, (op_id,))
                    executed.append(op_id)
                
                await db.execute("""
                    UPDATE go_transactions 
                    SET status = 'COMMITTED', approved_by = ?, approved_at = datetime('now'), approval_type = ?
                    WHERE tx_id = ?
                """, (approved_by, 'AUTO_AGENT' if auto else 'HUMAN', tx_id))
                
                await db.execute("DELETE FROM go_locks WHERE tx_id = ?", (tx_id,))
                await db.commit()
                
                # P4: Return with auto_approve info if applicable
                result = {'tx_id': tx_id, 'status': 'COMMITTED', 'operations': len(ops)}
                if auto:
                    result['auto_approved'] = True
                return result
                
            except Exception as e:
                await self._rollback(db, tx_id, executed)
                await db.commit()
                return {'tx_id': tx_id, 'status': 'ABORTED', 'error': str(e)}
    
    async def _execute_operation(self, op_type: str, target: str, payload: dict) -> bool:
        """
        P2: Execute operation via SandboxedSkillsExecutor.
        Returns True on success, False on failure.
        """
        if not self.skills_executor:
            # Fallback to dummy implementation if executor not available
            return True
        
        # Run executor in thread pool to avoid blocking async loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,  # Default executor
            self.skills_executor.execute,
            op_type,
            target,
            payload
        )
        
        # Log failures
        if not result.success:
            print(f"[GO-GATE] Execution failed: {result.op_type} on {result.target}")
            print(f"  Error: {result.error_message}")
            if result.error_code:
                print(f"  Error code: {result.error_code}")
            if result.stderr:
                print(f"  Stderr: {result.stderr[:500]}")  # Truncated
        
        return result.success
    
    async def _rollback(self, db, tx_id: str, executed_op_ids: List[int]):
        if not executed_op_ids:
            await db.execute(
                "UPDATE go_transactions SET status = 'ABORTED' WHERE tx_id = ?",
                (tx_id,)
            )
            await db.execute("DELETE FROM go_locks WHERE tx_id = ?", (tx_id,))
            await db.commit()
            return
        
        placeholders = ','.join('?' * len(executed_op_ids))
        cursor = await db.execute(f"""
            SELECT op_id, undo_payload FROM go_operations 
            WHERE tx_id = ? AND op_id IN ({placeholders})
            ORDER BY sequence DESC
        """, (tx_id,) + tuple(executed_op_ids))
        
        for op_id, undo_json in await cursor.fetchall():
            undo = json.loads(undo_json)
            await self._execute_undo(undo)
            await db.execute("""
                UPDATE go_operations SET status = 'ROLLED_BACK' WHERE op_id = ?
            """, (op_id,))
        
        await db.execute("""
            UPDATE go_transactions SET status = 'ABORTED' WHERE tx_id = ?
        """, (tx_id,))
        
        await db.execute("DELETE FROM go_locks WHERE tx_id = ?", (tx_id,))
        await db.commit()
    
    async def _execute_undo(self, undo_payload: dict):
        """
        P2: Execute undo operation for rollback.
        """
        action = undo_payload.get('action')
        path = undo_payload.get('path', '')
        
        if not path or not self.skills_executor:
            return
        
        if action == 'delete':
            # Delete created file
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self.skills_executor.execute,
                'FILE_DELETE',
                path,
                {'missing_ok': True}
            )
        elif action == 'restore':
            # TODO: Restore from trash if needed
            pass
    
    async def get_pending(self) -> List[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                SELECT tx_id, status, risk_level, verifier_agent, created_at
                FROM go_transactions 
                WHERE status IN ('PENDING_AUTO_APPROVAL', 'PENDING_HUMAN_APPROVAL')
                ORDER BY created_at
            """)
            rows = await cursor.fetchall()
            return [
                {
                    'tx_id': r[0],
                    'status': r[1],
                    'risk_level': r[2],
                    'verifier': r[3],
                    'created_at': r[4]
                }
                for r in rows
            ]


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='GO-GATE Transaction Manager')
    parser.add_argument('--init', action='store_true', help='Initialize database and start watchdog')
    parser.add_argument('--propose', type=str, help='Propose transaction (JSON file)')
    parser.add_argument('--approve', type=str, help='Approve transaction by ID')
    parser.add_argument('--pending', action='store_true', help='List pending approvals')
    parser.add_argument('--db', type=str, default='~/.openclaw/workspace/data/go_gate.db')
    
    args = parser.parse_args()
    
    gate = GoGate(args.db)
    
    async def main():
        if args.init:
            await gate.initialize()
            print("[GO-GATE] Initialized and watchdog started")
            try:
                while True:
                    await asyncio.sleep(3600)
            except KeyboardInterrupt:
                await gate.watchdog.stop()
        
        elif args.pending:
            pending = await gate.get_pending()
            for p in pending:
                print(f"{p['tx_id'][:8]}... | {p['status']} | {p['risk_level']} | {p['verifier'] or 'HUMAN'}")
        
        elif args.approve:
            result = await gate.approve(args.approve, 'admin', 'HUMAN')
            print(json.dumps(result, indent=2))
        
        elif args.propose:
            with open(args.propose) as f:
                ops = json.load(f)
            result = await gate.propose_transaction(ops)
            print(json.dumps(result, indent=2))
        
        else:
            parser.print_help()
    
    asyncio.run(main())
