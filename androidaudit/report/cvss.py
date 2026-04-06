from __future__ import annotations
from cvss import CVSS3

def calculate_cvss(vector: str) -> float:
    """Calculate the base CVSS 3.1 score given a vector."""
    try:
        if not vector.startswith("CVSS:3.1/"):
            return 0.0
        c = CVSS3(vector)
        return float(c.scores()[0])
    except Exception:
        return 0.0
