"""
Helpers to import/export topology data as JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from logic.topology_manager import TopologyManager


class TopologyIO:
    """Utility methods for JSON serialization of the topology."""

    @staticmethod
    def export_to_json(manager: TopologyManager, file_path: str) -> None:
        """Dump the current topology state to a JSON file."""
        payload: Dict[str, Any] = manager.to_dict()
        path = Path(file_path).expanduser().resolve()
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def import_from_json(manager: TopologyManager, file_path: str) -> None:
        """Load topology state from a JSON file."""
        path = Path(file_path).expanduser().resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        manager.load_from_dict(data)


__all__ = ["TopologyIO"]

