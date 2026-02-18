"""
Normalizer package.
Auto-detects and normalises events from any supported SIEM or syslog format.
"""

from .syslog_parser import parse as parse_syslog, detect_format
from .splunk import map_splunk_hec
from .elastic import map_elastic

__all__ = ["parse_syslog", "detect_format", "map_splunk_hec", "map_elastic"]
