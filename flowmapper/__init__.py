"""flowmapper – turn Illumio traffic flows into application architecture graphs."""
from .graph import FlowGraph
from .parsers import detect_format, load_flows, load_many

__version__ = "0.1.0"
__all__ = ["FlowGraph", "detect_format", "load_flows", "load_many", "__version__"]
