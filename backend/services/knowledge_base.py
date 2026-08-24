from backend.models.schemas import ThreatCategory
from backend.rag.config import THREAT_INTEL_DIR


def list_threat_categories() -> list[ThreatCategory]:
    """Discover available threat types directly from data/threat_intel/*.txt.

    description is the document's own first line -- not written or curated here --
    so this never claims knowledge-base content that doesn't actually exist.
    """
    categories = []
    for file_path in sorted(THREAT_INTEL_DIR.glob("*.txt")):
        text = file_path.read_text(encoding="utf-8")
        first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
        categories.append(
            ThreatCategory(threat_type=file_path.stem, source=file_path.name, description=first_line)
        )
    return categories
