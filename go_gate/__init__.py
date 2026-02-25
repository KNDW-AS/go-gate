"""
GO-GATE: Database-Grade Safety for AI Agents

A two-phase commit system for AI agent operations with fail-closed security,
human-in-the-loop approvals, and comprehensive audit trails.

Example:
    >>> import asyncio
    >>> from go_gate import GoGate
    >>> 
    >>> async def main():
    ...     gate = GoGate()
    ...     result = await gate.execute({
    ...         'op_type': 'FILE_WRITE',
    ...         'target': '/tmp/safe/output.txt',
    ...         'payload': {'content': 'Hello World'}
    ...     })
    ...     print(result.status)  # COMMITTED or PENDING_HUMAN_APPROVAL
    >>> 
    >>> asyncio.run(main())
"""

__version__ = "0.1.0"
__author__ = "William Park"
__license__ = "Apache-2.0"

# Lazy imports to avoid circular dependencies
def __getattr__(name):
    if name == "GoGate":
        from go_gate.core.go_gate import GoGate
        return GoGate
    if name == "SandboxedSkillsExecutor":
        from go_gate.core.skills_executor import SandboxedSkillsExecutor
        return SandboxedSkillsExecutor
    if name == "ToolRegistry":
        from go_gate.core.tool_registry import ToolRegistry
        return ToolRegistry
    raise AttributeError(f"module 'go_gate' has no attribute '{name}'")

__all__ = ["GoGate", "SandboxedSkillsExecutor", "ToolRegistry"]
