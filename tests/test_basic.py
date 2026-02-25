"""
Tests for GO-GATE package.

These are placeholder tests to be expanded as the project grows.
"""

import pytest


def test_import_package():
    """Test that the package can be imported."""
    import go_gate

    assert go_gate.__version__ == "0.1.0"


def test_import_core():
    """Test that core modules can be imported."""
    from go_gate.core.go_gate import GoGate
    from go_gate.core.tool_registry import ToolRegistry, OpType
    from go_gate.core.skills_executor import SandboxedSkillsExecutor

    assert GoGate is not None
    assert ToolRegistry is not None
    assert OpType is not None
    assert SandboxedSkillsExecutor is not None


def test_op_type_enum():
    """Test that OpType enum has expected values."""
    from go_gate.core.tool_registry import OpType

    assert OpType.FILE_WRITE.value == "FILE_WRITE"
    assert OpType.FILE_DELETE.value == "FILE_DELETE"
    assert OpType.SHELL_EXEC.value == "SHELL_EXEC"
