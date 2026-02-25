"""
Aeris Skills Registry
=====================
Samling av skills som implementerer TwoPhaseSkill eller SimpleSkill.
"""

try:
    from .filesystem import FileSystemSkill
except ImportError:
    FileSystemSkill = None

try:
    from .code_edit import CodeEditSkill
except ImportError:
    CodeEditSkill = None

try:
    from .memory_skill import MemorySkill
except ImportError:
    MemorySkill = None

__all__ = ["FileSystemSkill", "CodeEditSkill", "MemorySkill"]
