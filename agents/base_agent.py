from enum import Enum
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from abc import ABC, abstractmethod

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NEEDS_REVIEW = "NEEDS_REVIEW"

class AgentResult(BaseModel):
    verdict: str = Field(..., description="Short verdict statement from the agent")
    risk_level: RiskLevel = Field(..., description="Assessed risk classification")
    confidence: float = Field(..., description="Confidence score between 0.0 and 1.0")
    reasons: List[str] = Field(default_factory=list, description="Bullet points supporting the verdict")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Extracted keys/metadata from analysis")
    next_steps: List[str] = Field(default_factory=list, description="Recommended immediate actions")
    agent_name: str = Field(..., description="Identifier name of the agent")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Time of assessment")

class BaseAgent(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """The identifying name of this agent."""
        pass

    @abstractmethod
    async def run(self, input_data: dict) -> AgentResult:
        """
        Execute the agent's core analysis logic.
        
        Args:
            input_data (dict): Generic input parameters dictionary (e.g., {"text": "..."})
            
        Returns:
            AgentResult: Normalized classification output from the agent
        """
        pass
