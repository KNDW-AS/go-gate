# GO-GATE API Reference

## Core Concepts

### Transaction Flow

```
PREPARING → PENDING_AUTO_APPROVAL → COMMITTED
     ↓
PENDING_HUMAN_APPROVAL (HIGH risk or auto_approve=false)
     ↓
COMMITTED / ABORTED
```

### Policy Engine

Policies define how operations are handled based on risk level.

**Risk Levels:**
- `LOW` – Auto-approved if threshold met
- `MEDIUM` – Auto-approved with higher threshold
- `HIGH` – Always requires human approval

**Policy Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `op_type` | string | Operation type (FILE_WRITE, SHELL_EXEC, etc.) |
| `default_risk` | string | LOW, MEDIUM, or HIGH |
| `verification_threshold` | float | 0.0-1.0 confidence required for auto-approve |
| `auto_approve_allowed` | bool | Whether auto-approval is permitted |
| `verifier_agent` | string | **Optional** – Custom verifier for this operation type |

> **Note:** `verifier_agent` is optional. If the field does not exist or is null, 
> `verifier` becomes `None` and the flow remains safe (fail-closed). The transaction 
> will proceed through the standard approval path based on risk level and threshold.

### GoGate Class

#### `GoGate(db_path: str)`

Initialize GO-GATE with a SQLite database path.

```python
from go_gate import GoGate

gate = GoGate(db_path='/path/to/go_gate.db')
```

#### `async propose_transaction(operations: List[dict], proposer: str = 'agent') -> dict`

Propose a new transaction for execution.

**Parameters:**
- `operations`: List of operation dictionaries
- `proposer`: Identifier for the proposing agent

**Returns:**
```python
{
    'tx_id': 'uuid-string',
    'status': 'COMMITTED' | 'PENDING_HUMAN_APPROVAL' | 'ABORTED',
    'risk_level': 'LOW' | 'MEDIUM' | 'HIGH',
    'operations_executed': 2
}
```

**Example:**
```python
result = await gate.propose_transaction([
    {
        'type': 'FILE_WRITE',
        'target': '/path/to/file.txt',
        'payload': {'content': 'Hello World'}
    }
], proposer='my_agent')
```

#### `async commit(tx_id: str, committer: str, auto: bool = False) -> dict`

Commit a pending transaction.

#### `async abort(tx_id: str, reason: str) -> dict`

Abort a pending transaction.

### Operation Types

Built-in operation types:

| Type | Risk | Auto-Approve | Description |
|------|------|--------------|-------------|
| `FILE_WRITE` | LOW | Yes | Write content to file |
| `FILE_DELETE` | MEDIUM | Yes | Delete file |
| `GIT_COMMIT` | MEDIUM | Yes | Git commit |
| `GIT_PUSH` | HIGH | No | Push to remote |
| `SHELL_EXEC` | HIGH | No | Execute shell command |

### Fail-Closed Behavior

GO-GATE implements fail-closed security:

1. **Unknown operation types** → Treated as HIGH risk
2. **Missing policies** → Auto-approve disabled
3. **Verification failures** → Transaction ABORTED
4. **Timeout/exception** → Transaction ABORTED
5. **Missing verifier_agent** → `verifier` is `None`, safe fallback to standard flow

## SandboxedSkillsExecutor

### `get_executor(audit_callback=None)`

Factory function to create a sandboxed executor.

```python
from go_gate.core.skills_executor import get_executor

executor = get_executor(audit_callback=my_audit_function)
```

### ExecutionResult

```python
@dataclass
class ExecutionResult:
    success: bool
    op_type: str
    return_code: int
    stdout: str
    stderr: str
    error_message: Optional[str]
    error_code: Optional[str]
```

## Error Codes

| Code | Description |
|------|-------------|
| `SANDBOX_VIOLATION` | Path outside allowed workspaces |
| `PATH_TRAVERSAL` | Detected path traversal attempt |
| `GIT_FAILED` | Git operation failed |
| `EXEC_FAILED` | Command execution failed |
| `TIMEOUT` | Operation exceeded time limit |

## Security Notes

- All file paths are validated against `ALLOWED_WORKSPACES`
- Shell commands run with `shell=False` (list args only)
- Git operations use `GIT_TERMINAL_PROMPT=0` (no interactive prompts)
- Subprocess timeout prevents runaway operations
- All operations are logged to `go_audit` table
