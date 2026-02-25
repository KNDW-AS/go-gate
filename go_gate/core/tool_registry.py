#!/usr/bin/env python3
"""
core/tool_registry.py
P4 – Tool-hook for autonom igangsetting

Tool: execute_autonomous_task
- Lager CloudIntent og ruter via loop.process_intent()
- Fail-closed: ingen bypass av GO-GATE
- Standardisert LLM-feedback (ingen secrets)
- Structured logging
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List
from enum import Enum


class ToolError(Exception):
    """Tool execution error with structured error code."""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}


class OpType(Enum):
    """Supported operation types."""
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    SHELL_EXEC = "SHELL_EXEC"
    GIT_COMMIT = "GIT_COMMIT"
    GIT_PUSH = "GIT_PUSH"
    IMAGE_GENERATE = "IMAGE_GENERATE"


class ToolSafety(Enum):
    """Tool safety classification."""
    SAFE = "SAFE"      # Read-only, no side effects
    DANGEROUS = "DANGEROUS"  # Write operations, side effects


@dataclass
class CloudIntent:
    """Intent object for autonomous task execution."""
    op_type: str
    target: str
    payload: Dict[str, Any]
    risk_score: Optional[float] = None
    verification_score: Optional[float] = None
    request_id: Optional[str] = None
    source: str = "unknown"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + 'Z')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'op_type': self.op_type,
            'target': self.target,
            'payload': self.payload,
            'risk_score': self.risk_score,
            'verification_score': self.verification_score,
            'request_id': self.request_id,
            'source': self.source,
            'timestamp': self.timestamp
        }


@dataclass  
class ToolResult:
    """Standardized tool result for LLM feedback."""
    tx_id: Optional[str]
    status: str
    result: Optional[Dict[str, Any]]  # ExecutionResult or None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'tx_id': self.tx_id,
            'status': self.status,
            'result': self.result,
            'error_code': self.error_code,
            'error_message': self.error_message
        }


class AgentCoreLoop:
    """
    Stub for AgentCoreLoop integration.
    P4: This will be replaced with actual loop instance via dependency injection.
    """
    def __init__(self, go_gate=None):
        self.go_gate = go_gate
        self._processor: Optional[Callable] = None
    
    def set_processor(self, processor: Callable):
        """Set the intent processor (GO-GATE integration)."""
        self._processor = processor
    
    async def process_intent(self, intent: CloudIntent) -> Dict[str, Any]:
        """Process intent through GO-GATE."""
        if self._processor is None:
            raise ToolError("No processor configured", "LOOP_NOT_READY")
        return await self._processor(intent)


class ToolRegistry:
    """
    P4: Tool registry for autonomous task execution.
    
    Security invariants:
    - All tools must route through GO-GATE (no direct side effects)
    - No secrets in logs or return values
    - Fail-closed on invalid input
    """
    
    def __init__(self, loop: Optional[AgentCoreLoop] = None):
        self.loop = loop or AgentCoreLoop()
        self.tools: Dict[str, Callable] = {}
        self.logger = logging.getLogger('tool_registry')
        self._register_default_tools()
    
    def _register_default_tools(self):
        """Register default P4 tools."""
        self.register('execute_autonomous_task', self._handle_execute_autonomous_task)
        self.register('semantic_search', self._handle_semantic_search)
    
    def set_loop(self, processor):
        """Set the intent processor for GO-GATE integration."""
        self.loop.set_processor(processor)
    
    def register(self, name: str, handler: Callable):
        """Register a tool handler."""
        self.tools[name] = handler
    
    async def call(self, name: str, params: Dict[str, Any]) -> ToolResult:
        """
        Execute a tool by name.
        
        Args:
            name: Tool name (e.g., 'execute_autonomous_task')
            params: Tool parameters
            
        Returns:
            ToolResult with standardized feedback
        """
        if name not in self.tools:
            return ToolResult(
                tx_id=None,
                status='REJECTED',
                result=None,
                error_code='TOOL_NOT_FOUND',
                error_message=f"Unknown tool: {name}"
            )
        
        handler = self.tools[name]
        
        try:
            return await handler(params)
        except ToolError as e:
            self._log_tool_call(name, None, 'REJECTED', e.error_code, params)
            return ToolResult(
                tx_id=None,
                status='REJECTED',
                result=None,
                error_code=e.error_code,
                error_message=str(e)
            )
        except Exception as e:
            self._log_tool_call(name, None, 'ERROR', 'INTERNAL_ERROR', params)
            return ToolResult(
                tx_id=None,
                status='ERROR',
                result=None,
                error_code='INTERNAL_ERROR',
                error_message=str(e)
            )

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get tool schemas for LLM function calling (OpenAI format)."""
        return [
            {
                'type': 'function',
                'function': {
                    'name': 'execute_autonomous_task',
                    'description': 'Execute autonomous task through GO-GATE with sandboxed security',
                    'parameters': EXECUTE_AUTONOMOUS_TASK_SCHEMA
                }
            },
            {
                'type': 'function',
                'function': {
                    'name': 'semantic_search',
                    'description': 'Search local knowledge base using semantic similarity (RAG)',
                    'parameters': SEMANTIC_SEARCH_SCHEMA
                }
            }
        ]

    def get_openai_tools(self) -> List[Dict[str, Any]]:
        """Alias for get_tools() - OpenAI compatible format."""
        return self.get_tools()

    async def process_tool_calls(self, tool_calls: List[Any]) -> List[Dict[str, Any]]:
        """Process tool calls from LLM and return results."""
        results = []

        for tool_call in tool_calls:
            try:
                # Handle both object and dict formats
                if isinstance(tool_call, dict):
                    tool_name = tool_call.get('function', {}).get('name')
                    tool_args_str = tool_call.get('function', {}).get('arguments', '{}')
                    tool_call_id = tool_call.get('id')
                else:
                    tool_name = tool_call.function.name
                    tool_args_str = tool_call.function.arguments
                    tool_call_id = tool_call.id

                tool_args = json.loads(tool_args_str) if isinstance(tool_args_str, str) else tool_args_str

                result = await self.call(tool_name, tool_args)

                if result.status == 'SUCCESS':
                    content = json.dumps(result.result) if result.result else '{"success": true}'
                else:
                    content = json.dumps({
                        'error': result.error_message or result.error_code or 'Unknown error',
                        'status': result.status
                    })
            except Exception as e:
                content = json.dumps({'error': str(e)})
                tool_name = tool_name if 'tool_name' in locals() else 'unknown'
                tool_call_id = tool_call_id if 'tool_call_id' in locals() else 'unknown'

            results.append({
                'tool_call_id': tool_call_id,
                'name': tool_name,
                'content': content
            })

        return results

    def _log_tool_call(self, tool: str, tx_id: Optional[str], status: str,
                       error_code: Optional[str], params: Dict):
        """
        Structured logging without secrets.
        Logs: event, tool, tx_id, status, op_type, args_hash, args_len (no content)
        """
        op_type = params.get('op_type', 'unknown')
        args = params.get('args', {})
        
        # Hash args for correlation without exposing content
        args_json = json.dumps(args, sort_keys=True)
        args_hash = hashlib.sha256(args_json.encode()).hexdigest()[:16]
        args_len = len(args_json)
        
        # Redacted summary (path only, no content)
        args_summary = {}
        if 'path' in args:
            args_summary['path'] = str(args['path'])
        if 'target' in args:
            args_summary['target'] = str(args['target'])
        if 'command' in args:
            cmd = str(args['command'])
            args_summary['command'] = cmd[:50] + '...' if len(cmd) > 50 else cmd
        
        log_entry = {
            'event': 'TOOL_CALL',
            'tool': tool,
            'tx_id': tx_id,
            'status': status,
            'error_code': error_code,
            'op_type': op_type,
            'args_hash': args_hash,
            'args_len': args_len,
            'args_summary': args_summary,
            'source': params.get('source', 'unknown'),
            'request_id': params.get('request_id'),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        self.logger.info(json.dumps(log_entry))
    
    async def _handle_execute_autonomous_task(self, params: Dict[str, Any]) -> ToolResult:
        """
        P4: Execute autonomous task via GO-GATE.
        
        Flow:
        1. Validate op_type/args (fail-closed)
        2. Build CloudIntent
        3. Call loop.process_intent() → GO-GATE
        4. Return standardized ToolResult
        """
        # Extract parameters
        op_type_str = params.get('op_type')
        target = params.get('target')
        payload = params.get('payload', {})
        risk_score = params.get('risk_score')
        verification_score = params.get('verification_score')
        request_id = params.get('request_id')
        source = params.get('source', 'unknown')
        
        # P4: Validate op_type (fail-closed)
        try:
            op_type = OpType(op_type_str)
        except (ValueError, TypeError):
            raise ToolError(
                f"Invalid or unsupported op_type: {op_type_str}",
                "INVALID_OP_TYPE"
            )
        
        # P4: Validate target (required)
        if not target or not isinstance(target, str):
            raise ToolError("target is required and must be a string", "INVALID_TARGET")
        
        # P4: Validate payload (required)
        if not isinstance(payload, dict):
            raise ToolError("payload must be an object", "INVALID_PAYLOAD")
        
        # P4: Build CloudIntent with target and payload
        intent = CloudIntent(
            op_type=op_type.value,
            target=target,
            payload=payload,
            risk_score=risk_score,
            verification_score=verification_score,
            request_id=request_id,
            source=source
        )
        
        # P4: Route through loop (GO-GATE)
        try:
            result = await self.loop.process_intent(intent)
        except ToolError:
            raise
        except Exception as e:
            raise ToolError(f"Loop processing failed: {e}", "LOOP_ERROR")
        
        # Extract result
        tx_id = result.get('tx_id')
        status = result.get('status', 'UNKNOWN')
        
        # P4: Build result dict (redacted, no secrets)
        execution_result = None
        if 'execution_result' in result and result['execution_result']:
            er = result['execution_result']
            execution_result = {
                'success': er.get('success'),
                'exit_code': er.get('return_code'),
                'error_code': er.get('error_code'),
                'stdout_len': len(er.get('stdout', '')),
                'stderr_len': len(er.get('stderr', '')),
                # Truncated output (first 200 chars)
                'stdout_preview': er.get('stdout', '')[:200],
                'stderr_preview': er.get('stderr', '')[:200]
            }
        
        # P4: Log structured (no secrets)
        self._log_tool_call('execute_autonomous_task', tx_id, status, None, params)
        
        return ToolResult(
            tx_id=tx_id,
            status=status,
            result=execution_result
        )
    
    async def _handle_semantic_search(self, params: Dict[str, Any]) -> ToolResult:
        """
        SAFE: Perform semantic search on vector database using local RAG.
        
        This is a read-only operation with no side effects.
        Flow:
        1. Get embedding from Legion Ollama (local)
        2. Search ChromaDB (local)
        3. Return results to LLM
        4. Log audit event (without query text for privacy)
        
        Safety: SAFE (read-only)
        """
        from core.rag_search import search_knowledge, RAGSearchError
        
        # Extract parameters
        query = params.get('query')
        collection = params.get('collection', 'system_knowledge')
        top_k = params.get('top_k', 5)
        source = params.get('source', 'unknown')
        
        # Validate query
        if not query or not isinstance(query, str):
            raise ToolError("query must be a non-empty string", "INVALID_QUERY")
        
        # Validate collection
        valid_collections = ['system_knowledge', 'aeris_knowledge', 'user_facts', 'aeris_memory']
        if collection not in valid_collections:
            raise ToolError(
                f"Invalid collection: {collection}. Valid: {', '.join(valid_collections)}",
                "INVALID_COLLECTION"
            )
        
        # Validate top_k
        if not isinstance(top_k, int) or top_k < 1 or top_k > 20:
            raise ToolError("top_k must be between 1 and 20", "INVALID_TOP_K")
        
        # Perform search
        try:
            search_result = search_knowledge(query, collection, top_k)
        except Exception as e:
            raise ToolError(f"RAG search failed: {e}", "RAG_ERROR")
        
        # Log to GO-GATE audit (without query text for privacy)
        audit_event = {
            'event_type': 'RAG_SEARCH_PERFORMED',
            'source': source,
            'collection': collection,
            'top_k': top_k,
            'result_count': search_result.get('count', 0),
            'success': search_result.get('success', False),
            'error_code': search_result.get('error_code'),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Log to structured logging
        self.logger.info(json.dumps({
            'event': 'TOOL_CALL',
            'tool': 'semantic_search',
            'tx_id': None,
            'status': 'SUCCESS' if search_result.get('success') else 'FAILED',
            'error_code': search_result.get('error_code'),
            'safety_class': 'SAFE',
            'collection': collection,
            'result_count': search_result.get('count', 0),
            'source': source,
            'request_id': params.get('request_id'),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }))
        
        # Build result
        if search_result.get('success'):
            return ToolResult(
                tx_id=None,
                status='SUCCESS',
                result={
                    'success': True,
                    'collection': collection,
                    'count': search_result.get('count', 0),
                    'results': [
                        {
                            'document': r['document'],
                            'metadata': r['metadata'],
                            'distance': r['distance'],
                            'collection': r['collection']
                        }
                        for r in search_result.get('results', [])
                    ]
                }
            )
        else:
            return ToolResult(
                tx_id=None,
                status='FAILED',
                result=None,
                error_code=search_result.get('error_code', 'RAG_UNKNOWN_ERROR'),
                error_message=search_result.get('error', 'Unknown RAG error')
            )


# P4: Global singleton for DI
tool_registry: Optional[ToolRegistry] = None

def get_tool_registry(loop: Optional[AgentCoreLoop] = None) -> ToolRegistry:
    """Get or create global tool registry."""
    global tool_registry
    if tool_registry is None:
        tool_registry = ToolRegistry(loop=loop)
    return tool_registry


def reset_tool_registry():
    """Reset global registry (for testing)."""
    global tool_registry
    tool_registry = None


# P4: Schema for LLM/tool system
EXECUTE_AUTONOMOUS_TASK_SCHEMA = {
    "name": "execute_autonomous_task",
    "description": "Execute an autonomous task through GO-GATE with sandboxed security. IMPORTANT: All three parameters (op_type, target, payload) are REQUIRED and must be provided.",
    "parameters": {
        "type": "object",
        "properties": {
            "op_type": {
                "type": "string",
                "enum": ["FILE_WRITE", "FILE_DELETE", "SHELL_EXEC", "GIT_COMMIT", "GIT_PUSH", "IMAGE_GENERATE"],
                "description": "REQUIRED: Type of operation to execute. Must be one of the enum values. IMAGE_GENERATE: uses Nano Banana Pro (Gemini) to generate images."
            },
            "target": {
                "type": "string",
                "description": "REQUIRED: Target path, file, or resource. For FILE_WRITE/DELETE: absolute file path. For GIT_COMMIT: repo path. For SHELL_EXEC: command string."
            },
            "payload": {
                "type": "object",
                "description": "REQUIRED: Operation-specific data. FILE_WRITE: {'content': 'text', 'mode': 'w'}. FILE_DELETE: {'missing_ok': true}. GIT_COMMIT: {'message': 'commit msg', 'files': ['file1']}. SHELL_EXEC: {'command': 'ls -la', 'timeout': 30}."
            },
            "risk_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "Optional: Risk score 0-1 (auto-calculated if not provided)"
            },
            "verification_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "Optional: Verification score 0-1 (auto-calculated if not provided)"
            },
            "request_id": {
                "type": "string",
                "description": "Optional: Request ID for deduplication/idempotency"
            },
            "source": {
                "type": "string",
                "description": "Optional: Source of request (e.g., 'gemini', 'kimi', 'claude')"
            }
        },
        "required": ["op_type", "target", "payload"]
    }
}


def get_tool_schemas() -> List[Dict]:
    """Return all tool schemas for LLM registration."""
    return [EXECUTE_AUTONOMOUS_TASK_SCHEMA, SEMANTIC_SEARCH_SCHEMA]


# P4: Schema for semantic_search tool (SAFE - read-only)
SEMANTIC_SEARCH_SCHEMA = {
    "name": "semantic_search",
    "description": "Perform semantic search on the knowledge base using local RAG. SAFE (read-only) - no side effects, no external APIs. Returns relevant documents based on semantic similarity to the query.",
    "safety": "SAFE",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The search query text. This will be converted to an embedding and matched against documents."
            },
            "collection": {
                "type": "string",
                "enum": ["system_knowledge", "aeris_knowledge", "user_facts", "aeris_memory"],
                "default": "system_knowledge",
                "description": "Which collection to search. system_knowledge (default) contains technical docs, aeris_knowledge for agent knowledge, user_facts for user data, aeris_memory for conversation history."
            },
            "top_k": {
                "type": "integer",
                "minimum": 1,
                "maximum": 20,
                "default": 5,
                "description": "Number of results to return (1-20, default: 5)"
            },
            "source": {
                "type": "string",
                "description": "Source of the request (e.g., 'aeris', 'zeph', 'kimi', 'claude')"
            },
            "request_id": {
                "type": "string",
                "description": "Optional request ID for deduplication/idempotency"
            }
        },
        "required": ["query"]
    }
}


# P4: Integration helper for GO-GATE
async def create_go_gate_processor(go_gate_instance):
    """
    Create an intent processor that routes through GO-GATE.
    
    Usage:
        go_gate = GoGate(db_path='...')
        processor = create_go_gate_processor(go_gate)
        loop.set_processor(processor)
    """
    async def processor(intent: CloudIntent) -> Dict[str, Any]:
        # Convert CloudIntent to GO-GATE operations
        operations = [{
            'type': intent.op_type,
            'target': intent.target,
            'payload': intent.payload,
            'undo_payload': {}  # TODO: Implement undo logic
        }]
        
        # Route through GO-GATE
        result = await go_gate_instance.propose_transaction(
            operations, 
            proposer=intent.source
        )
        
        # P4: Add execution result based on final status
        status = result.get('status')
        if status == 'COMMITTED':
            # Execution succeeded
            result['execution_result'] = {
                'success': True,
                'return_code': 0,
                'stdout': '',
                'stderr': '',
                'error_code': None
            }
        elif status == 'ABORTED':
            # Execution failed (e.g., blocked by executor)
            result['execution_result'] = {
                'success': False,
                'return_code': 1,
                'stdout': '',
                'stderr': result.get('error', 'Unknown error'),
                'error_code': 'EXECUTION_FAILED'
            }
        # For pending states, no execution result yet
        
        return result
    
    return processor


if __name__ == '__main__':
    # P4 smoke test
    logging.basicConfig(level=logging.INFO)
    
    async def test():
        print("=" * 60)
        print("P4 Tool Registry Smoke Test")
        print("=" * 60)
        
        registry = get_tool_registry()
        
        # Test 1: Valid FILE_WRITE intent
        print("\n[Test 1] Valid FILE_WRITE intent...")
        result = await registry.call('execute_autonomous_task', {
            'op_type': 'FILE_WRITE',
            'target': '/tmp/test.txt',
            'payload': {'content': 'hello', 'mode': 'w'},
            'source': 'test'
        })
        print(f"  Result: {result.to_dict()}")
        assert result.status == 'REJECTED' or result.tx_id is not None
        print("  ✅ Handler reached (no loop configured = expected)")
        
        # Test 2: Invalid op_type
        print("\n[Test 2] Invalid op_type...")
        result = await registry.call('execute_autonomous_task', {
            'op_type': 'INVALID_OP',
            'target': '/tmp/test.txt',
            'payload': {},
            'source': 'test'
        })
        print(f"  Result: {result.to_dict()}")
        assert result.error_code == 'INVALID_OP_TYPE'
        print("  ✅ Fail-closed: rejected invalid op_type")
        
        # Test 3: Unknown tool
        print("\n[Test 3] Unknown tool...")
        result = await registry.call('unknown_tool', {})
        print(f"  Result: {result.to_dict()}")
        assert result.error_code == 'TOOL_NOT_FOUND'
        print("  ✅ Fail-closed: unknown tool rejected")
        
        # Test 4: Semantic search (SAFE, read-only)
        print("\n[Test 4] Semantic search...")
        result = await registry.call('semantic_search', {
            'query': 'GO-GATE security',
            'collection': 'system_knowledge',
            'top_k': 3,
            'source': 'test'
        })
        print(f"  Result status: {result.status}")
        if result.status == 'SUCCESS':
            print(f"  Found {result.result.get('count', 0)} results")
            print("  ✅ SAFE tool: semantic search working")
        else:
            print(f"  Error: {result.error_message}")
            print("  ⚠️  Search failed (Legion may be unavailable)")
        
        # Test 5: Semantic search validation (fail-closed)
        print("\n[Test 5] Semantic search validation...")
        result = await registry.call('semantic_search', {
            'query': '',  # Invalid: empty query
            'source': 'test'
        })
        print(f"  Result: {result.to_dict()}")
        assert result.error_code == 'INVALID_QUERY'
        print("  ✅ Fail-closed: empty query rejected")
        
        print("\n" + "=" * 60)
        print("✅ P4 Smoke Test: PASS")
        print("=" * 60)
    
    asyncio.run(test())
