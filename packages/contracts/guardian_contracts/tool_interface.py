from abc import ABC, abstractmethod
from typing import Tuple, Any, Dict, Optional
from pydantic import BaseModel

class ToolExecutionResult(BaseModel):
    tool_name: str
    exit_code: int
    stdout_artifact_sha256: str
    stderr_artifact_sha256: Optional[str] = None
    parsed_output: Dict[str, Any]
    duration_ms: int

class ToolInterface(ABC):
    """Unified Tool.run(input) -> (output, evidence) protocol."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def run(self, input_data: Dict[str, Any]) -> Tuple[Dict[str, Any], ToolExecutionResult]:
        """Executes tool logic deterministically and returns parsed payload plus raw execution evidence."""
        pass
