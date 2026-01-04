import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

class Reporter:
    """Handles report generation and output."""
    
    def __init__(self, output_format: str = "json"):
        self.output_format = output_format
        self.reports: List[Dict[str, Any]] = []
    
    def add_report(self, data: Dict[str, Any]) -> None:
        """Add a report entry."""
        data["timestamp"] = datetime.now().isoformat()
        self.reports.append(data)
    
    def save(self, filepath: str) -> None:
        """Save reports to file."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            if self.output_format == "json":
                json.dump(self.reports, f, indent=2)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all reports."""
        return {
            "total_reports": len(self.reports),
            "timestamp": datetime.now().isoformat()
        }