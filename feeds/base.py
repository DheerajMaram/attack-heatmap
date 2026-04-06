"""
Abstract base class and shared dataclass for all threat feed integrations.
All feed implementations must inherit from BaseFeed and return List[FeedEntry].
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FeedEntry:
    """Normalized representation of a single threat feed record."""
    ioc: str                           # IP, URL, hash, domain
    ioc_type: str                      # "ip", "url", "sha256", "md5", "domain"
    malware_family: Optional[str]      # e.g. "Emotet", "Cobalt Strike"
    threat_type: Optional[str]         # e.g. "botnet_cc", "payload_delivery"
    source: str                        # feed name (e.g. "threatfox")
    tags: List[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    # Direct ATT&CK technique IDs — set by feeds that carry their own mappings
    # (e.g. CISA KEV). When populated, the STIX mapper step is bypassed for
    # this entry and these IDs are used directly.
    technique_ids: Optional[List[str]] = field(default_factory=list)

    def __post_init__(self):
        # Normalize malware family name to title-case for consistent lookups
        if self.malware_family:
            self.malware_family = self.malware_family.strip()
        self.ioc_type = self.ioc_type.lower() if self.ioc_type else self.ioc_type


class BaseFeed(ABC):
    """Abstract base for all threat feed integrations."""
    name: str = "base"

    @abstractmethod
    def fetch(self) -> List[FeedEntry]:
        """Fetch live data and normalize to a list of FeedEntry objects."""
        ...

    def __repr__(self) -> str:
        return f"<Feed: {self.name}>"
