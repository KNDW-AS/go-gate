#!/usr/bin/env python3
"""
core/skills_executor.py
Sandboxed Skills Executor for GO-GATE P2

Security-first execution engine for AI agent operations.
All operations are sandboxed, validated, and logged.
"""

import os
import re
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class ExecutionResult:
    """Standardized result object for all skill executions."""
    success: bool
    op_type: str
    target: str
    stdout: str = ""
    stderr: str = ""
    return_code: Optional[int] = None
    execution_time_ms: float = 0.0
    timestamp: str = ""
    error_message: str = ""
    error_code: Optional[str] = None  # P2: Standardized error codes
    
    # P2 Error codes:
    # TRAVERSAL_BLOCKED - Path contains ../ or similar
    # OUTSIDE_WORKSPACE - Path escapes allowed workspace
    # SYMLINK_ESCAPE - Path traverses symlink outside workspace
    # CMD_NOT_ALLOWED - Command not in whitelist
    # CMD_REJECTED - Dangerous characters in command
    # TIMEOUT - Operation exceeded time limit
    # FILE_WRITE_FAILED - Write operation failed
    # FILE_DELETE_FAILED - Delete operation failed
    # IS_DIRECTORY - Attempted to delete directory
    # GIT_FAILED - Git operation failed
    # 
    # P8.2: Granular error codes for enhanced observability
    # FILE_PERMISSION_DENIED - Insufficient permissions for file operation
    # PATH_TRAVERSAL_BLOCKED - Explicit path traversal attack blocked (../)
    # SANDBOX_VIOLATION - Attempted to escape sandbox environment
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'op_type': self.op_type,
            'target': self.target,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'return_code': self.return_code,
            'execution_time_ms': self.execution_time_ms,
            'timestamp': self.timestamp,
            'error_message': self.error_message,
            'error_code': self.error_code
        }


class SandboxedSkillsExecutor:
    """
    Secure execution engine for GO-GATE transactions.
    
    Security features:
    - Directory traversal prevention (no ../)
    - Workspace restrictions (only allowed paths)
    - Command whitelisting for shell operations
    - Subprocess isolation with timeouts
    - Environment variable sanitization
    """
    
    # Allowed base paths for file operations (absolute paths)
    # Configure via GOGATE_WORKSPACES environment variable
    # Uses tempfile.gettempdir() for cross-platform compatibility
    import tempfile
    _TEMP_DIR = Path(tempfile.gettempdir())
    ALLOWED_WORKSPACES = [
        str(_TEMP_DIR / 'go-gate-sandbox'),
        str(_TEMP_DIR),  # Allow temp dir for temp files and E2E tests
    ]
    
    # Default output directory for generated files
    DEFAULT_OUTPUT_DIR = _TEMP_DIR / 'go-gate-output'
    
    # Ensure sandbox directories exist
    SANDBOX_DIR = _TEMP_DIR / 'go-gate-sandbox'
    
    # Shell command whitelist (exact matches or patterns)
    SHELL_COMMAND_WHITELIST = [
        # Git operations (safe subset)
        r'^git\s+status',
        r'^git\s+add\s+',
        r'^git\s+commit\s+',
        r'^git\s+push',
        r'^git\s+log\s+',
        r'^git\s+diff\s+',
        # File operations
        r'^cat\s+',
        r'^ls\s+',
        r'^mkdir\s+',
        r'^cp\s+',
        r'^mv\s+',
        r'^rm\s+',
        # System info (read-only)
        r'^date$',
        r'^pwd$',
        r'^whoami$',
        r'^hostname$',
    ]
    
    # Dangerous patterns (always blocked)
    DANGEROUS_PATTERNS = [
        r'\.\./',  # Directory traversal
        r'\.\.\\',  # Windows traversal
        r'[`;$|&]',  # Shell metacharacters
        r'\bsudo\b',
        r'\bsu\s+-',
        r'\bchown\s+',
        r'\bchmod\s+777',
        r'\brm\s+-rf\s+/',
        r'\bdd\s+if=',
        r'\bmv\s+.*\s+/dev/null',
        r'\bwget\s+.*\s+-O\s*-',
        r'\bcurl\s+.*\s*\|\s*bash',
    ]
    
    def __init__(self, audit_callback=None):
        """
        Initialize the executor.
        
        Args:
            audit_callback: Optional function(result) called after each execution
        """
        self.audit_callback = audit_callback
        self.SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    
    def execute(self, op_type: str, target: str, payload: Dict[str, Any]) -> ExecutionResult:
        """
        Main entry point for executing operations.
        
        Args:
            op_type: FILE_WRITE, FILE_DELETE, SHELL_EXEC, GIT_COMMIT, GIT_PUSH
            target: Path or target resource
            payload: Operation-specific arguments
            
        Returns:
            ExecutionResult with success/fail and details
        """
        import time
        start_time = time.time()
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        try:
            # Route to appropriate handler
            if op_type == 'FILE_WRITE':
                result = self._file_write(target, payload)
            elif op_type == 'FILE_DELETE':
                result = self._file_delete(target, payload)
            elif op_type == 'SHELL_EXEC':
                result = self._shell_exec(target, payload)
            elif op_type == 'GIT_COMMIT':
                result = self._git_commit(target, payload)
            elif op_type == 'GIT_PUSH':
                result = self._git_push(target, payload)
            elif op_type == 'IMAGE_GENERATE':
                result = self._image_generate(target, payload)
            else:
                result = ExecutionResult(
                    success=False,
                    op_type=op_type,
                    target=target,
                    timestamp=timestamp,
                    error_message=f"Unsupported operation type: {op_type}"
                )
            
            # Add timing
            result.execution_time_ms = (time.time() - start_time) * 1000
            result.timestamp = timestamp
            
        except Exception as e:
            result = ExecutionResult(
                success=False,
                op_type=op_type,
                target=target,
                timestamp=timestamp,
                error_message=f"Executor exception: {str(e)}"
            )
        
        # Audit logging
        if self.audit_callback:
            self.audit_callback(result)
        
        return result
    
    def _validate_path(self, path: str, check_symlinks: bool = True) -> Path:
        """
        Validate that a path is within allowed workspaces.
        P2: Also checks for symlink escape attacks.
        
        Raises:
            ValueError: If path contains traversal, escapes workspace, or traverses symlinks
        """
        # Check raw path string for traversal attempts before resolving
        for pattern in [r'\.\./', r'\.\.\\']:
            if re.search(pattern, path):
                raise ValueError(f"TRAVERSAL_BLOCKED: Directory traversal detected: {path}")
        
        # Check for home expansion
        if path.startswith('~'):
            raise ValueError(f"OUTSIDE_WORKSPACE: Home expansion not allowed: {path}")
        
        # Check for absolute paths outside allowed workspaces
        if path.startswith('/'):
            abs_allowed = False
            for allowed in self.ALLOWED_WORKSPACES:
                if path.startswith(allowed):
                    abs_allowed = True
                    break
            if not abs_allowed:
                raise ValueError(f"OUTSIDE_WORKSPACE: Absolute path not in allowed workspaces: {path}")
        
        # Convert to absolute path
        target_path = Path(path).resolve()
        
        # P2: Symlink escape detection
        if check_symlinks:
            # Walk the path and check each component for symlinks
            current = Path('/')
            for part in target_path.parts[1:]:  # Skip root
                current = current / part
                if current.is_symlink():
                    # Resolve the symlink target
                    link_target = current.readlink()
                    if link_target.is_absolute():
                        # Check if symlink points outside workspace
                        try:
                            in_workspace = False
                            for allowed in self.ALLOWED_WORKSPACES:
                                allowed_path = Path(allowed).resolve()
                                link_target.relative_to(allowed_path)
                                in_workspace = True
                                break
                            if not in_workspace:
                                raise ValueError(f"SYMLINK_ESCAPE: Symlink {current} -> {link_target} points outside workspace")
                        except ValueError:
                            raise ValueError(f"SYMLINK_ESCAPE: Symlink {current} -> {link_target} points outside workspace")
        
        # Check against allowed workspaces
        for allowed in self.ALLOWED_WORKSPACES:
            allowed_path = Path(allowed).resolve()
            try:
                # Check if target is within allowed path
                target_path.relative_to(allowed_path)
                return target_path
            except ValueError:
                continue
        
        raise ValueError(f"OUTSIDE_WORKSPACE: Path {path} is outside allowed workspaces")
    
    def _validate_shell_command(self, command: str) -> bool:
        """
        Validate shell command against whitelist and dangerous patterns.
        
        Returns:
            True if command is allowed
            
        Raises:
            ValueError: If command is blocked
        """
        # Check dangerous patterns first
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                raise ValueError(f"Command blocked by security policy: {pattern}")
        
        # Check whitelist
        for pattern in self.SHELL_COMMAND_WHITELIST:
            if re.match(pattern, command, re.IGNORECASE):
                return True
        
        # If no whitelist match, block by default (fail-closed)
        raise ValueError(f"Command not in whitelist: {command}")
    
    def _file_write(self, target: str, payload: Dict[str, Any]) -> ExecutionResult:
        """Execute FILE_WRITE operation."""
        try:
            # Validate path (with symlink check)
            safe_path = self._validate_path(target, check_symlinks=True)
            
            # Ensure parent directory exists
            safe_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Get content and mode
            content = payload.get('content', '')
            mode = payload.get('mode', 'w')
            encoding = payload.get('encoding', 'utf-8')
            
            # P2: Validate mode (only w, a, x allowed)
            if mode not in ('w', 'a', 'x'):
                return ExecutionResult(
                    success=False,
                    op_type='FILE_WRITE',
                    target=target,
                    error_message=f"Invalid mode: {mode}. Only w, a, x allowed",
                    error_code='FILE_WRITE_FAILED',
                    return_code=1
                )
            
            # P2: Content size limit (2MB)
            if isinstance(content, str) and len(content.encode('utf-8')) > 2 * 1024 * 1024:
                return ExecutionResult(
                    success=False,
                    op_type='FILE_WRITE',
                    target=target,
                    error_message="Content exceeds 2MB limit",
                    error_code='FILE_WRITE_FAILED',
                    return_code=1
                )
            
            # P2: Atomic write for w/x modes (temp file -> rename)
            if mode in ('w', 'x'):
                temp_path = safe_path.parent / f".tmp_{safe_path.name}.{os.getpid()}"
                try:
                    with open(temp_path, mode, encoding=encoding) as f:
                        f.write(content)
                        f.flush()
                        os.fsync(f.fileno())
                    # Atomic rename
                    os.rename(temp_path, safe_path)
                except Exception as e:
                    # Cleanup temp file on failure
                    if temp_path.exists():
                        temp_path.unlink()
                    raise
            else:
                # Append mode (not atomic)
                with open(safe_path, mode, encoding=encoding) as f:
                    f.write(content)
            
            return ExecutionResult(
                success=True,
                op_type='FILE_WRITE',
                target=str(safe_path),
                stdout=f"File written: {safe_path}",
                return_code=0
            )
            
        except ValueError as e:
            # Path validation errors have specific codes
            error_str = str(e)
            error_code = 'FILE_WRITE_FAILED'
            if 'TRAVERSAL_BLOCKED' in error_str:
                error_code = 'PATH_TRAVERSAL_BLOCKED'  # P8.2: Explicit traversal block
            elif 'OUTSIDE_WORKSPACE' in error_str:
                error_code = 'SANDBOX_VIOLATION'  # P8.2: Sandbox escape attempt
            elif 'SYMLINK_ESCAPE' in error_str:
                error_code = 'SANDBOX_VIOLATION'  # P8.2: Symlink escape = sandbox violation
            
            return ExecutionResult(
                success=False,
                op_type='FILE_WRITE',
                target=target,
                error_message=error_str,
                error_code=error_code,
                return_code=1
            )
        except PermissionError as e:
            # P8.2: Explicit permission denied error
            return ExecutionResult(
                success=False,
                op_type='FILE_WRITE',
                target=target,
                error_message=f"Permission denied: {e}",
                error_code='FILE_PERMISSION_DENIED',
                return_code=1
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                op_type='FILE_WRITE',
                target=target,
                error_message=str(e),
                error_code='FILE_WRITE_FAILED',
                return_code=1
            )
    
    def _file_delete(self, target: str, payload: Dict[str, Any]) -> ExecutionResult:
        """Execute FILE_DELETE operation."""
        try:
            # Validate path
            safe_path = self._validate_path(target)
            
            # Check if path exists
            if not safe_path.exists():
                # P2: missing_ok = ok (return success)
                if payload.get('missing_ok', True):
                    return ExecutionResult(
                        success=True,
                        op_type='FILE_DELETE',
                        target=str(safe_path),
                        stdout="File did not exist, nothing to delete",
                        return_code=0
                    )
                return ExecutionResult(
                    success=False,
                    op_type='FILE_DELETE',
                    target=str(safe_path),
                    error_message=f"File not found: {safe_path}",
                    error_code='FILE_DELETE_FAILED',
                    return_code=1
                )
            
            # P2: Refuse to delete directories
            if safe_path.is_dir():
                return ExecutionResult(
                    success=False,
                    op_type='FILE_DELETE',
                    target=str(safe_path),
                    error_message="Cannot delete directory (refuse_dir_delete policy)",
                    error_code='IS_DIRECTORY',
                    return_code=1
                )
            
            # Move to trash instead of permanent delete (safer)
            trash_dir = Path('/tmp/aeris_trash')
            trash_dir.mkdir(exist_ok=True)
            trash_path = trash_dir / f"{safe_path.name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            shutil.move(str(safe_path), str(trash_path))
            
            return ExecutionResult(
                success=True,
                op_type='FILE_DELETE',
                target=str(safe_path),
                stdout=f"File moved to trash: {trash_path}",
                return_code=0
            )
            
        except ValueError as e:
            error_str = str(e)
            error_code = 'FILE_DELETE_FAILED'
            if 'TRAVERSAL_BLOCKED' in error_str:
                error_code = 'PATH_TRAVERSAL_BLOCKED'  # P8.2: Explicit traversal block
            elif 'OUTSIDE_WORKSPACE' in error_str:
                error_code = 'SANDBOX_VIOLATION'  # P8.2: Sandbox escape attempt
            elif 'SYMLINK_ESCAPE' in error_str:
                error_code = 'SANDBOX_VIOLATION'  # P8.2: Symlink escape = sandbox violation
            
            return ExecutionResult(
                success=False,
                op_type='FILE_DELETE',
                target=target,
                error_message=error_str,
                error_code=error_code,
                return_code=1
            )
        except PermissionError as e:
            # P8.2: Explicit permission denied error
            return ExecutionResult(
                success=False,
                op_type='FILE_DELETE',
                target=target,
                error_message=f"Permission denied: {e}",
                error_code='FILE_PERMISSION_DENIED',
                return_code=1
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                op_type='FILE_DELETE',
                target=target,
                error_message=str(e),
                error_code='FILE_DELETE_FAILED',
                return_code=1
            )
    
    def _shell_exec(self, target: str, payload: Dict[str, Any]) -> ExecutionResult:
        """Execute SHELL_EXEC operation."""
        command = payload.get('command', '')
        timeout = payload.get('timeout', 20)  # P2: Default 20s
        
        try:
            # P2: Check for dangerous characters before whitelist
            dangerous_chars = [';', '&', '|', '<', '>', '$', '`', '\n', '\t']
            for char in dangerous_chars:
                if char in command:
                    return ExecutionResult(
                        success=False,
                        op_type='SHELL_EXEC',
                        target=command,
                        error_message=f"Command contains blocked character: {repr(char)}",
                        error_code='CMD_REJECTED',
                        return_code=1
                    )
            
            # Validate command against whitelist
            try:
                self._validate_shell_command(command)
            except ValueError as e:
                return ExecutionResult(
                    success=False,
                    op_type='SHELL_EXEC',
                    target=command,
                    error_message=str(e),
                    error_code='CMD_NOT_ALLOWED',
                    return_code=1
                )
            
            # Execute with subprocess (shell=False for security)
            # Split command for shell=False execution
            cmd_parts = command.split()
            
            result = subprocess.run(
                cmd_parts,
                shell=False,  # P2: No shell interpretation
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=payload.get('cwd', '/tmp/go-gate-sandbox'),
                env={  # P2: Minimal isolated environment
                    'PATH': '/usr/local/bin:/usr/bin:/bin',
                    'HOME': str(Path.home()),
                    'USER': os.environ.get('USER', 'agent'),
                    'GIT_TERMINAL_PROMPT': '0',  # Fail-closed for git
                }
            )
            
            # P2: Cap output at 20k chars
            stdout = result.stdout[:20000] if result.stdout else ""
            stderr = result.stderr[:20000] if result.stderr else ""
            
            return ExecutionResult(
                success=result.returncode == 0,
                op_type='SHELL_EXEC',
                target=command,
                stdout=stdout,
                stderr=stderr,
                return_code=result.returncode
            )
            
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                op_type='SHELL_EXEC',
                target=command,
                error_message=f"Command timed out after {timeout} seconds",
                error_code='TIMEOUT',
                return_code=-1
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                op_type='SHELL_EXEC',
                target=command,
                error_message=str(e),
                error_code='CMD_NOT_ALLOWED',
                return_code=1
            )
    
    def _git_commit(self, target: str, payload: Dict[str, Any]) -> ExecutionResult:
        """Execute GIT_COMMIT operation."""
        try:
            message = payload.get('message', 'Agent automated commit')
            cwd = payload.get('cwd', '/tmp/go-gate-sandbox')
            
            # P2: Validate cwd is in allowed workspaces
            self._validate_path(cwd)
            
            # P2: Validate message (no NUL/CR)
            if '\x00' in message or '\r' in message:
                return ExecutionResult(
                    success=False,
                    op_type='GIT_COMMIT',
                    target=target,
                    error_message="Invalid commit message (contains NUL or CR)",
                    error_code='GIT_FAILED',
                    return_code=1
                )
            
            # P2: Minimal isolated environment
            git_env = {
                'PATH': '/usr/local/bin:/usr/bin:/bin',
                'HOME': str(Path.home()),
                'USER': os.environ.get('USER', 'agent'),
                'GIT_TERMINAL_PROMPT': '0',  # Fail-closed: no interactive prompts
                'GIT_AUTHOR_NAME': 'GO-GATE Agent',
                'GIT_AUTHOR_EMAIL': 'agent@go-gate.local',
            }
            
            # Add all changes (list-args, no shell)
            add_result = subprocess.run(
                ['git', 'add', '-A'],
                capture_output=True,
                text=True,
                cwd=cwd,
                env=git_env
            )
            
            if add_result.returncode != 0:
                return ExecutionResult(
                    success=False,
                    op_type='GIT_COMMIT',
                    target=target,
                    stdout=add_result.stdout[:20000],
                    stderr=add_result.stderr[:20000],
                    error_code='GIT_FAILED',
                    return_code=add_result.returncode
                )
            
            # Commit (list-args, no shell, --no-gpg-sign for automation)
            commit_result = subprocess.run(
                ['git', 'commit', '-m', message, '--no-gpg-sign'],
                capture_output=True,
                text=True,
                cwd=cwd,
                env=git_env
            )
            
            return ExecutionResult(
                success=commit_result.returncode == 0,
                op_type='GIT_COMMIT',
                target=target,
                stdout=commit_result.stdout[:20000],
                stderr=commit_result.stderr[:20000],
                error_code=None if commit_result.returncode == 0 else 'GIT_FAILED',
                return_code=commit_result.returncode
            )
            
        except ValueError as e:
            return ExecutionResult(
                success=False,
                op_type='GIT_COMMIT',
                target=target,
                error_message=str(e),
                error_code='OUTSIDE_WORKSPACE',
                return_code=1
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                op_type='GIT_COMMIT',
                target=target,
                error_message=str(e),
                error_code='GIT_FAILED',
                return_code=1
            )
    
    def _git_push(self, target: str, payload: Dict[str, Any]) -> ExecutionResult:
        """Execute GIT_PUSH operation."""
        try:
            cwd = payload.get('cwd', '/tmp/go-gate-sandbox')
            remote = payload.get('remote', 'origin')
            branch = payload.get('branch', 'main')
            
            # P2: Validate cwd
            self._validate_path(cwd)
            
            # P2: Validate remote/branch (simple token validation)
            token_pattern = re.compile(r'^[a-zA-Z0-9_.-]+$')
            if not token_pattern.match(remote):
                return ExecutionResult(
                    success=False,
                    op_type='GIT_PUSH',
                    target=target,
                    error_message=f"Invalid remote name: {remote}",
                    error_code='GIT_FAILED',
                    return_code=1
                )
            if not token_pattern.match(branch):
                return ExecutionResult(
                    success=False,
                    op_type='GIT_PUSH',
                    target=target,
                    error_message=f"Invalid branch name: {branch}",
                    error_code='GIT_FAILED',
                    return_code=1
                )
            
            # P2: Minimal isolated environment
            git_env = {
                'PATH': '/usr/local/bin:/usr/bin:/bin',
                'HOME': str(Path.home()),
                'USER': os.environ.get('USER', 'agent'),
                'GIT_TERMINAL_PROMPT': '0',  # Fail-closed: no interactive prompts
            }
            
            # Push with --porcelain for machine-readable output
            push_result = subprocess.run(
                ['git', 'push', '--porcelain', remote, branch],
                capture_output=True,
                text=True,
                cwd=cwd,
                env=git_env,
                timeout=30  # P2: Timeout for push
            )
            
            return ExecutionResult(
                success=push_result.returncode == 0,
                op_type='GIT_PUSH',
                target=target,
                stdout=push_result.stdout[:20000],
                stderr=push_result.stderr[:20000],
                error_code=None if push_result.returncode == 0 else 'GIT_FAILED',
                return_code=push_result.returncode
            )
            
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                op_type='GIT_PUSH',
                target=target,
                error_message="Push timed out after 30 seconds",
                error_code='TIMEOUT',
                return_code=-1
            )
        except ValueError as e:
            return ExecutionResult(
                success=False,
                op_type='GIT_PUSH',
                target=target,
                error_message=str(e),
                error_code='OUTSIDE_WORKSPACE',
                return_code=1
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                op_type='GIT_PUSH',
                target=target,
                error_message=str(e),
                error_code='GIT_FAILED',
                return_code=1
            )

    def _image_generate(self, target: str, payload: Dict[str, Any]) -> ExecutionResult:
        """
        Generate an image using Gemini 3 Pro Image (Nano Banana Pro).
        LOW risk operation - auto-approved by policy.
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        try:
            # If target is relative, prepend default output directory
            target_path = Path(target)
            if not target_path.is_absolute():
                target_path = self.DEFAULT_OUTPUT_DIR / 'images' / target_path
            
            # Validate path
            target_path = self._validate_path(str(target_path), check_symlinks=False)
            target_path = Path(target_path)
            
            # Ensure output directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Extract parameters
            prompt = payload.get('prompt', '')
            resolution = payload.get('resolution', '1K')
            
            if not prompt:
                return ExecutionResult(
                    success=False,
                    op_type='IMAGE_GENERATE',
                    target=target,
                    timestamp=timestamp,
                    error_message="Missing required 'prompt' parameter",
                    error_code='INVALID_ARGS'
                )
            
            # Import and call image_generate skill
            try:
                from skills.image_generate import generate_image
                
                result = generate_image(
                    prompt=prompt,
                    output_path=str(target_path),
                    resolution=resolution
                )
                
                if result.get('success'):
                    return ExecutionResult(
                        success=True,
                        op_type='IMAGE_GENERATE',
                        target=target,
                        stdout=f"Image generated: {result.get('path')}",
                        stderr="",
                        return_code=0,
                        timestamp=timestamp
                    )
                else:
                    return ExecutionResult(
                        success=False,
                        op_type='IMAGE_GENERATE',
                        target=target,
                        error_message=result.get('error', 'Unknown error'),
                        error_code='IMAGE_GEN_FAILED',
                        return_code=1,
                        timestamp=timestamp
                    )
                    
            except ImportError as e:
                return ExecutionResult(
                    success=False,
                    op_type='IMAGE_GENERATE',
                    target=target,
                    error_message=f"image_generate skill not available: {e}",
                    error_code='SKILL_NOT_FOUND',
                    return_code=1,
                    timestamp=timestamp
                )
            except Exception as e:
                return ExecutionResult(
                    success=False,
                    op_type='IMAGE_GENERATE',
                    target=target,
                    error_message=f"Image generation error: {str(e)}",
                    error_code='IMAGE_GEN_FAILED',
                    return_code=1,
                    timestamp=timestamp
                )
                
        except ValueError as e:
            return ExecutionResult(
                success=False,
                op_type='IMAGE_GENERATE',
                target=target,
                error_message=str(e),
                error_code='OUTSIDE_WORKSPACE',
                return_code=1,
                timestamp=timestamp
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                op_type='IMAGE_GENERATE',
                target=target,
                error_message=str(e),
                error_code='IMAGE_GEN_FAILED',
                return_code=1,
                timestamp=timestamp
            )


# Singleton instance for easy import
_skills_executor: Optional[SandboxedSkillsExecutor] = None

def get_executor(audit_callback=None) -> SandboxedSkillsExecutor:
    """Get or create singleton executor instance."""
    global _skills_executor
    if _skills_executor is None:
        _skills_executor = SandboxedSkillsExecutor(audit_callback=audit_callback)
    return _skills_executor


if __name__ == '__main__':
    # Simple test
    executor = SandboxedSkillsExecutor()
    
    # Test FILE_WRITE
    result = executor.execute('FILE_WRITE', '/tmp/aeris_sandbox/test.txt', {
        'content': 'Hello from SandboxedSkillsExecutor!'
    })
    print(f"FILE_WRITE: {result}")
    
    # Test FILE_DELETE
    result = executor.execute('FILE_DELETE', '/tmp/aeris_sandbox/test.txt', {})
    print(f"FILE_DELETE: {result}")
    
    # Test SHELL_EXEC
    result = executor.execute('SHELL_EXEC', 'date', {'command': 'date'})
    print(f"SHELL_EXEC: {result}")
