"""
AEGIS AI Incident Investigation Agent
Modular AI-driven investigation component for AEGIS Security Operations.
"""

__version__ = "0.1.0"

from aegis_agent.pipeline_adapter import LinuxLogPipelineAdapter
from aegis_agent.linux_parser import LinuxTelemetryParser

__all__ = [
    "LinuxLogPipelineAdapter",
    "LinuxTelemetryParser",
]


